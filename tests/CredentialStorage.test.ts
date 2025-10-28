import { describe, it, expect, beforeEach } from "vitest";
import { buffCV, principalCV, stringUtf8CV, uintCV, listCV, tupleCV } from "@stacks/transactions";

const ERR_NOT_AUTHORIZED = 100;
const ERR_INVALID_DOCTOR = 101;
const ERR_INVALID_ID = 102;
const ERR_CREDENTIAL_EXISTS = 103;
const ERR_CREDENTIAL_NOT_FOUND = 104;
const ERR_INVALID_HASH = 105;
const ERR_INVALID_EXPIRY = 106;
const ERR_INVALID_TYPE = 107;
const ERR_INVALID_METADATA = 108;
const ERR_OWNERSHIP_MISMATCH = 113;
const ERR_MAX_CREDENTIALS = 126;

interface Credential {
  hash: Uint8Array;
  expiry: number;
  issuer: string;
  type: string;
  status: boolean;
  metadata: string;
  owner: string;
}

interface CredentialType {
  level: number;
  category: string;
}

interface DoctorStats {
  total: number;
  active: number;
  revoked: number;
}

type Result<T, E = number> = { ok: boolean; value: T | E };

class CredentialStorageMock {
  state: {
    nextCredentialId: number;
    maxCredentialsPerDoctor: number;
    authorityContract: string | null;
    credentials: Map<string, Credential>;
    credentialIndex: Map<string, number[]>;
    credentialTypes: Map<string, CredentialType>;
    doctorStats: Map<string, DoctorStats>;
    nftOwners: Map<number, string>;
  } = {
    nextCredentialId: 1,
    maxCredentialsPerDoctor: 50,
    authorityContract: null,
    credentials: new Map(),
    credentialIndex: new Map(),
    credentialTypes: new Map(),
    doctorStats: new Map(),
    nftOwners: new Map(),
  };
  blockHeight: number = 100;
  caller: string = "ST1DOCTOR";

  constructor() {
    this.reset();
  }

  reset() {
    this.state = {
      nextCredentialId: 1,
      maxCredentialsPerDoctor: 50,
      authorityContract: null,
      credentials: new Map(),
      credentialIndex: new Map(),
      credentialTypes: new Map(),
      doctorStats: new Map(),
      nftOwners: new Map(),
    };
    this.blockHeight = 100;
    this.caller = "ST1DOCTOR";
  }

  private getKey(doctor: string, id: number): string {
    return `${doctor}-${id}`;
  }

  setAuthorityContract(contract: string): Result<boolean> {
    if (this.caller !== contract) return { ok: false, value: ERR_NOT_AUTHORIZED };
    this.state.authorityContract = contract;
    return { ok: true, value: true };
  }

  setMaxCredentials(newMax: number): Result<boolean> {
    if (!this.state.authorityContract) return { ok: false, value: ERR_NOT_AUTHORIZED };
    if (newMax <= 0 || newMax > 100) return { ok: false, value: ERR_INVALID_METADATA };
    this.state.maxCredentialsPerDoctor = newMax;
    return { ok: true, value: true };
  }

  registerCredential(
    doctor: string,
    hash: Uint8Array,
    expiry: number,
    issuer: string,
    type: string,
    metadata: string
  ): Result<number> {
    if (doctor !== this.caller) return { ok: false, value: ERR_INVALID_DOCTOR };
    const id = this.state.nextCredentialId;
    const key = this.getKey(doctor, id);
    if (this.state.credentials.has(key)) return { ok: false, value: ERR_CREDENTIAL_EXISTS };
    const ids = this.state.credentialIndex.get(doctor) || [];
    if (ids.length >= this.state.maxCredentialsPerDoctor) return { ok: false, value: ERR_MAX_CREDENTIALS };
    if (hash.length !== 32) return { ok: false, value: ERR_INVALID_HASH };
    if (expiry <= this.blockHeight) return { ok: false, value: ERR_INVALID_EXPIRY };
    if (!this.state.credentialTypes.has(type)) return { ok: false, value: ERR_INVALID_TYPE };
    if (metadata.length > 256) return { ok: false, value: ERR_INVALID_METADATA };
    const cred: Credential = { hash, expiry, issuer, type, status: true, metadata, owner: doctor };
    this.state.credentials.set(key, cred);
    this.state.nftOwners.set(id, doctor);
    this.state.credentialIndex.set(doctor, [...ids, id]);
    const stats = this.state.doctorStats.get(doctor) || { total: 0, active: 0, revoked: 0 };
    this.state.doctorStats.set(doctor, { total: stats.total + 1, active: stats.active + 1, revoked: stats.revoked });
    this.state.nextCredentialId++;
    return { ok: true, value: id };
  }

  updateCredential(doctor: string, id: number, metadata: string, status: boolean): Result<boolean> {
    if (doctor !== this.caller) return { ok: false, value: ERR_INVALID_DOCTOR };
    if (id <= 0) return { ok: false, value: ERR_INVALID_ID };
    const key = this.getKey(doctor, id);
    const cred = this.state.credentials.get(key);
    if (!cred) return { ok: false, value: ERR_CREDENTIAL_NOT_FOUND };
    if (this.state.nftOwners.get(id) !== doctor) return { ok: false, value: ERR_OWNERSHIP_MISMATCH };
    if (metadata.length > 256) return { ok: false, value: ERR_INVALID_METADATA };
    this.state.credentials.set(key, { ...cred, metadata, status });
    return { ok: true, value: true };
  }

  transferCredential(id: number, recipient: string): Result<boolean> {
    const owner = this.state.nftOwners.get(id);
    if (!owner) return { ok: false, value: ERR_CREDENTIAL_NOT_FOUND };
    if (owner !== this.caller) return { ok: false, value: ERR_NOT_AUTHORIZED };
    this.state.nftOwners.set(id, recipient);
    const cred = this.state.credentials.get(this.getKey(owner, id));
    if (cred) this.state.credentials.set(this.getKey(owner, id), { ...cred, owner: recipient });
    return { ok: true, value: true };
  }

  revokeCredential(doctor: string, id: number): Result<boolean> {
    if (doctor !== this.caller) return { ok: false, value: ERR_INVALID_DOCTOR };
    const key = this.getKey(doctor, id);
    const cred = this.state.credentials.get(key);
    if (!cred) return { ok: false, value: ERR_CREDENTIAL_NOT_FOUND };
    if (!cred.status) return { ok: false, value: ERR_INVALID_STATUS };
    this.state.credentials.set(key, { ...cred, status: false });
    const stats = this.state.doctorStats.get(doctor)!;
    this.state.doctorStats.set(doctor, { total: stats.total, active: stats.active - 1, revoked: stats.revoked + 1 });
    return { ok: true, value: true };
  }

  addCredentialType(type: string, level: number, category: string): Result<boolean> {
    if (!this.state.authorityContract) return { ok: false, value: ERR_NOT_AUTHORIZED };
    if (this.state.credentialTypes.has(type)) return { ok: false, value: ERR_INVALID_TYPE };
    if (level > 10) return { ok: false, value: ERR_INVALID_METADATA };
    if (category.length === 0) return { ok: false, value: ERR_INVALID_CATEGORY };
    this.state.credentialTypes.set(type, { level, category });
    return { ok: true, value: true };
  }

  getCredentialCount(): Result<number> {
    return { ok: true, value: this.state.nextCredentialId };
  }

  getCredentialByIndex(doctor: string, index: number): Result<number> {
    const ids = this.state.credentialIndex.get(doctor) || [];
    if (index >= 50 || index >= ids.length) return { ok: false, value: ERR_INVALID_INDEX };
    return { ok: true, value: ids[index] };
  }

  checkCredentialExistence(doctor: string, id: number): Result<boolean> {
    return { ok: true, value: this.state.credentials.has(this.getKey(doctor, id)) };
  }

  // Mock helpers
  addMockType(type: string) {
    this.state.credentialTypes.set(type, { level: 5, category: "medical" });
  }
}

describe("CredentialStorage", () => {
  let contract: CredentialStorageMock;

  beforeEach(() => {
    contract = new CredentialStorageMock();
    contract.reset();
  });

  it("registers credential successfully", () => {
    contract.addMockType("medical");
    const hash = new Uint8Array(32).fill(1);
    const result = contract.registerCredential(
      "ST1DOCTOR",
      hash,
      200,
      "STISSUER",
      "medical",
      "Board certified"
    );
    expect(result.ok).toBe(true);
    expect(result.value).toBe(1);
    expect(contract.state.nftOwners.get(1)).toBe("ST1DOCTOR");
    expect(contract.state.doctorStats.get("ST1DOCTOR")?.total).toBe(1);
  });

  it("updates credential metadata", () => {
    contract.addMockType("medical");
    const hash = new Uint8Array(32).fill(1);
    contract.registerCredential("ST1DOCTOR", hash, 200, "STISSUER", "medical", "Old");
    const result = contract.updateCredential("ST1DOCTOR", 1, "Updated metadata", true);
    expect(result.ok).toBe(true);
    const key = contract["getKey"]("ST1DOCTOR", 1);
    expect(contract.state.credentials.get(key)?.metadata).toBe("Updated metadata");
  });

  it("transfers credential ownership", () => {
    contract.addMockType("medical");
    const hash = new Uint8Array(32).fill(1);
    contract.registerCredential("ST1DOCTOR", hash, 200, "STISSUER", "medical", "Cert");
    contract.caller = "ST1DOCTOR";
    const result = contract.transferCredential(1, "ST2RECIPIENT");
    expect(result.ok).toBe(true);
    expect(contract.state.nftOwners.get(1)).toBe("ST2RECIPIENT");
  });

  it("revokes credential", () => {
    contract.addMockType("medical");
    const hash = new Uint8Array(32).fill(1);
    contract.registerCredential("ST1DOCTOR", hash, 200, "STISSUER", "medical", "Cert");
    const result = contract.revokeCredential("ST1DOCTOR", 1);
    expect(result.ok).toBe(true);
    expect(contract.state.doctorStats.get("ST1DOCTOR")?.revoked).toBe(1);
    expect(contract.state.doctorStats.get("ST1DOCTOR")?.active).toBe(0);
  });

  it("adds credential type", () => {
    contract.state.authorityContract = "STADMIN";
    contract.caller = "STADMIN";
    const result = contract.addCredentialType("surgery", 8, "specialty");
    expect(result.ok).toBe(true);
    expect(contract.state.credentialTypes.get("surgery")?.level).toBe(8);
  });

  it("gets credential count", () => {
    contract.addMockType("medical");
    const hash = new Uint8Array(32).fill(1);
    contract.registerCredential("ST1DOCTOR", hash, 200, "STISSUER", "medical", "Cert");
    const result = contract.getCredentialCount();
    expect(result.ok).toBe(true);
    expect(result.value).toBe(2);
  });

  it("gets credential by index", () => {
    contract.addMockType("medical");
    const hash = new Uint8Array(32).fill(1);
    contract.registerCredential("ST1DOCTOR", hash, 200, "STISSUER", "medical", "Cert1");
    contract.registerCredential("ST1DOCTOR", hash, 200, "STISSUER", "medical", "Cert2");
    const result = contract.getCredentialByIndex("ST1DOCTOR", 1);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(2);
  });

  it("checks credential existence", () => {
    contract.addMockType("medical");
    const hash = new Uint8Array(32).fill(1);
    contract.registerCredential("ST1DOCTOR", hash, 200, "STISSUER", "medical", "Cert");
    const result = contract.checkCredentialExistence("ST1DOCTOR", 1);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
  });
});