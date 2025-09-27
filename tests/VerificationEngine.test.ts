import { describe, it, expect, beforeEach } from "vitest";
import { buffCV, principalCV, stringUtf8CV, uintCV } from "@stacks/transactions";

const ERR_NOT_AUTHORIZED = 100;
const ERR_INVALID_CREDENTIAL_ID = 101;
const ERR_CREDENTIAL_NOT_FOUND = 102;
const ERR_CREDENTIAL_EXPIRED = 103;
const ERR_CREDENTIAL_REVOKED = 104;
const ERR_INVALID_ISSUER = 105;
const ERR_INVALID_PROOF = 106;
const ERR_INVALID_DOCTOR = 107;
const ERR_INVALID_EXPIRY = 108;
const ERR_INVALID_HASH = 109;
const ERR_INVALID_TYPE = 110;
const ERR_INVALID_STATUS = 111;
const ERR_INVALID_METADATA = 124;
const ERR_VERIFICATION_FAILED = 129;

interface Credential {
  hash: Uint8Array;
  expiry: number;
  issuer: string;
  type: string;
  status: boolean;
  metadata: string;
}

interface VerificationEntry {
  credentialId: number;
  result: boolean;
  proof: Uint8Array;
}

interface BatchEntry {
  d: string;
  i: number;
  p: Uint8Array;
}

type Result<T, E = number> = { ok: boolean; value: T | E };

class VerificationEngineMock {
  state: {
    verificationFee: number;
    minProofThreshold: number;
    authorityContract: string | null;
    credentials: Map<string, Credential>;
    revocations: Map<number, boolean>;
    verifiers: Map<string, boolean>;
    verificationHistory: Map<string, VerificationEntry>;
    credentialTypes: Map<string, number>;
    accessRoles: Map<string, boolean>;
  } = {
    verificationFee: 10,
    minProofThreshold: 50,
    authorityContract: null,
    credentials: new Map(),
    revocations: new Map(),
    verifiers: new Map(),
    verificationHistory: new Map(),
    credentialTypes: new Map(),
    accessRoles: new Map(),
  };
  blockHeight: number = 100;
  caller: string = "ST1DOCTOR";
  stxTransfers: Array<{ amount: number; from: string; to: string }> = [];

  constructor() {
    this.reset();
  }

  reset() {
    this.state = {
      verificationFee: 10,
      minProofThreshold: 50,
      authorityContract: null,
      credentials: new Map(),
      revocations: new Map(),
      verifiers: new Map(),
      verificationHistory: new Map(),
      credentialTypes: new Map(),
      accessRoles: new Map(),
    };
    this.blockHeight = 100;
    this.caller = "ST1DOCTOR";
    this.stxTransfers = [];
  }

  private getCredentialKey(doctor: string, id: number): string {
    return `${doctor}-${id}`;
  }

  private getHistoryKey(doctor: string, verifier: string, timestamp: number): string {
    return `${doctor}-${verifier}-${timestamp}`;
  }

  private getRoleKey(principal: string, role: string): string {
    return `${principal}-${role}`;
  }

  setAuthorityContract(contract: string): Result<boolean> {
    if (this.caller !== contract) return { ok: false, value: ERR_NOT_AUTHORIZED };
    this.state.authorityContract = contract;
    return { ok: true, value: true };
  }

  setVerificationFee(newFee: number): Result<boolean> {
    if (!this.state.authorityContract) return { ok: false, value: ERR_NOT_AUTHORIZED };
    if (newFee <= 0) return { ok: false, value: ERR_INVALID_METADATA };
    this.state.verificationFee = newFee;
    return { ok: true, value: true };
  }

  setMinProofThreshold(newThreshold: number): Result<boolean> {
    if (!this.state.authorityContract) return { ok: false, value: ERR_NOT_AUTHORIZED };
    if (newThreshold < 50) return { ok: false, value: ERR_INVALID_METADATA };
    this.state.minProofThreshold = newThreshold;
    return { ok: true, value: true };
  }

  addVerifier(verifier: string): Result<boolean> {
    if (!this.state.authorityContract) return { ok: false, value: ERR_NOT_AUTHORIZED };
    if (this.state.verifiers.has(verifier)) return { ok: false, value: ERR_INVALID_VERIFIER };
    this.state.verifiers.set(verifier, true);
    return { ok: true, value: true };
  }

  removeVerifier(verifier: string): Result<boolean> {
    if (!this.state.authorityContract) return { ok: false, value: ERR_NOT_AUTHORIZED };
    this.state.verifiers.delete(verifier);
    return { ok: true, value: true };
  }

  verifyCredential(doctor: string, id: number, proof: Uint8Array): Result<boolean> {
    if (doctor !== this.caller) return { ok: false, value: ERR_INVALID_DOCTOR };
    if (id <= 0) return { ok: false, value: ERR_INVALID_CREDENTIAL_ID };
    if (proof.length !== 64) return { ok: false, value: ERR_INVALID_PROOF };
    const key = this.getCredentialKey(doctor, id);
    const cred = this.state.credentials.get(key);
    if (!cred) return { ok: false, value: ERR_CREDENTIAL_NOT_FOUND };
    if (this.state.revocations.get(id) === true) return { ok: false, value: ERR_CREDENTIAL_REVOKED };
    if (cred.expiry <= this.blockHeight) return { ok: false, value: ERR_CREDENTIAL_EXPIRED };
    if (!this.state.verifiers.get(cred.issuer)) return { ok: false, value: ERR_INVALID_ISSUER };
    if (!this.state.credentialTypes.has(cred.type)) return { ok: false, value: ERR_INVALID_TYPE };
    if (!cred.status) return { ok: false, value: ERR_INVALID_STATUS };
    if (cred.metadata.length > 256) return { ok: false, value: ERR_INVALID_METADATA };
    if (!this.state.authorityContract) return { ok: false, value: ERR_NOT_AUTHORIZED };
    this.stxTransfers.push({ amount: this.state.verificationFee, from: this.caller, to: this.state.authorityContract });
    const historyKey = this.getHistoryKey(doctor, this.caller, this.blockHeight);
    this.state.verificationHistory.set(historyKey, { credentialId: id, result: true, proof });
    return { ok: true, value: true };
  }

  batchVerifyCredentials(entries: BatchEntry[]): Result<boolean> {
    for (const entry of entries) {
      const result = this.verifyCredential(entry.d, entry.i, entry.p);
      if (!result.ok) return result;
    }
    return { ok: true, value: true };
  }

  getVerificationStatus(doctor: string, id: number): Result<boolean> {
    const key = this.getCredentialKey(doctor, id);
    const cred = this.state.credentials.get(key);
    if (!cred) return { ok: false, value: ERR_CREDENTIAL_NOT_FOUND };
    const notRevoked = this.state.revocations.get(id) !== true;
    const notExpired = cred.expiry > this.blockHeight;
    return { ok: true, value: notRevoked && notExpired && cred.status };
  }

  addCredentialType(type: string, level: number): Result<boolean> {
    if (!this.state.authorityContract) return { ok: false, value: ERR_NOT_AUTHORIZED };
    if (!this.state.credentialTypes.has(type)) return { ok: false, value: ERR_INVALID_TYPE };
    if (level > 10) return { ok: false, value: ERR_INVALID_METADATA };
    this.state.credentialTypes.set(type, level);
    return { ok: true, value: true };
  }

  assignRole(p: string, role: string): Result<boolean> {
    if (!this.state.authorityContract) return { ok: false, value: ERR_NOT_AUTHORIZED };
    if (!["admin", "verifier", "doctor"].includes(role)) return { ok: false, value: ERR_INVALID_METADATA };
    const key = this.getRoleKey(p, role);
    this.state.accessRoles.set(key, true);
    return { ok: true, value: true };
  }

  revokeRole(p: string, role: string): Result<boolean> {
    if (!this.state.authorityContract) return { ok: false, value: ERR_NOT_AUTHORIZED };
    const key = this.getRoleKey(p, role);
    this.state.accessRoles.delete(key);
    return { ok: true, value: true };
  }

  checkAccess(p: string, role: string): Result<boolean> {
    const key = this.getRoleKey(p, role);
    return { ok: true, value: this.state.accessRoles.get(key) || false };
  }

  // Mock helper to add credential for testing
  addMockCredential(doctor: string, id: number, cred: Credential) {
    const key = this.getCredentialKey(doctor, id);
    this.state.credentials.set(key, cred);
  }

  // Mock helper to revoke credential
  revokeMockCredential(id: number) {
    this.state.revocations.set(id, true);
  }
}

describe("VerificationEngine", () => {
  let contract: VerificationEngineMock;

  beforeEach(() => {
    contract = new VerificationEngineMock();
    contract.reset();
  });

  it("sets authority contract successfully", () => {
    contract.caller = "STAUTH";
    const result = contract.setAuthorityContract("STAUTH");
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    expect(contract.state.authorityContract).toBe("STAUTH");
  });

  it("rejects setting authority by unauthorized", () => {
    contract.caller = "ST1DOCTOR";
    const result = contract.setAuthorityContract("STAUTH");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_NOT_AUTHORIZED);
  });

  it("sets verification fee successfully", () => {
    contract.state.authorityContract = "STAUTH";
    const result = contract.setVerificationFee(20);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    expect(contract.state.verificationFee).toBe(20);
  });

  it("rejects setting fee without authority", () => {
    const result = contract.setVerificationFee(20);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_NOT_AUTHORIZED);
  });

  it("verifies credential successfully", () => {
    contract.state.authorityContract = "STAUTH";
    contract.state.verifiers.set("STISSUER", true);
    contract.state.credentialTypes.set("medical", 5);
    const proof = new Uint8Array(64).fill(1);
    const cred: Credential = {
      hash: new Uint8Array(32).fill(1),
      expiry: 200,
      issuer: "STISSUER",
      type: "medical",
      status: true,
      metadata: "Doctor credentials",
    };
    contract.addMockCredential("ST1DOCTOR", 1, cred);
    const result = contract.verifyCredential("ST1DOCTOR", 1, proof);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    expect(contract.stxTransfers).toEqual([{ amount: 10, from: "ST1DOCTOR", to: "STAUTH" }]);
    const historyKey = contract["getHistoryKey"]("ST1DOCTOR", "ST1DOCTOR", 100);
    const history = contract.state.verificationHistory.get(historyKey);
    expect(history?.credentialId).toBe(1);
    expect(history?.result).toBe(true);
  });

  it("rejects verification for expired credential", () => {
    contract.state.authorityContract = "STAUTH";
    contract.state.verifiers.set("STISSUER", true);
    contract.state.credentialTypes.set("medical", 5);
    const proof = new Uint8Array(64).fill(1);
    const cred: Credential = {
      hash: new Uint8Array(32).fill(1),
      expiry: 50,
      issuer: "STISSUER",
      type: "medical",
      status: true,
      metadata: "Doctor credentials",
    };
    contract.addMockCredential("ST1DOCTOR", 1, cred);
    const result = contract.verifyCredential("ST1DOCTOR", 1, proof);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_CREDENTIAL_EXPIRED);
  });

  it("batch verifies credentials successfully", () => {
    contract.state.authorityContract = "STAUTH";
    contract.state.verifiers.set("STISSUER", true);
    contract.state.credentialTypes.set("medical", 5);
    const proof = new Uint8Array(64).fill(1);
    const cred: Credential = {
      hash: new Uint8Array(32).fill(1),
      expiry: 200,
      issuer: "STISSUER",
      type: "medical",
      status: true,
      metadata: "Doctor credentials",
    };
    contract.addMockCredential("ST1DOCTOR", 1, cred);
    contract.addMockCredential("ST1DOCTOR", 2, cred);
    const entries: BatchEntry[] = [
      { d: "ST1DOCTOR", i: 1, p: proof },
      { d: "ST1DOCTOR", i: 2, p: proof },
    ];
    const result = contract.batchVerifyCredentials(entries);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    expect(contract.stxTransfers.length).toBe(2);
  });

  it("gets verification status correctly", () => {
    contract.state.verifiers.set("STISSUER", true);
    contract.state.credentialTypes.set("medical", 5);
    const cred: Credential = {
      hash: new Uint8Array(32).fill(1),
      expiry: 200,
      issuer: "STISSUER",
      type: "medical",
      status: true,
      metadata: "Doctor credentials",
    };
    contract.addMockCredential("ST1DOCTOR", 1, cred);
    const result = contract.getVerificationStatus("ST1DOCTOR", 1);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
  });

  it("adds credential type successfully", () => {
    contract.state.authorityContract = "STAUTH";
    contract.state.credentialTypes.set("medical", 0);
    const result = contract.addCredentialType("medical", 5);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    expect(contract.state.credentialTypes.get("medical")).toBe(5);
  });

  it("assigns role successfully", () => {
    contract.state.authorityContract = "STAUTH";
    const result = contract.assignRole("ST1DOCTOR", "doctor");
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    const roleKey = contract["getRoleKey"]("ST1DOCTOR", "doctor");
    expect(contract.state.accessRoles.get(roleKey)).toBe(true);
  });

  it("revokes role successfully", () => {
    contract.state.authorityContract = "STAUTH";
    const roleKey = contract["getRoleKey"]("ST1DOCTOR", "doctor");
    contract.state.accessRoles.set(roleKey, true);
    const result = contract.revokeRole("ST1DOCTOR", "doctor");
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    expect(contract.state.accessRoles.get(roleKey)).toBeUndefined();
  });

  it("checks access correctly", () => {
    const roleKey = contract["getRoleKey"]("ST1DOCTOR", "doctor");
    contract.state.accessRoles.set(roleKey, true);
    const result = contract.checkAccess("ST1DOCTOR", "doctor");
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
  });
});