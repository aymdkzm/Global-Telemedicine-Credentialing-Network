import { describe, it, expect, beforeEach } from "vitest";
import {
  buffCV,
  principalCV,
  stringUtf8CV,
  uintCV,
} from "@stacks/transactions";

const ERR_NOT_AUTHORIZED = 100;
const ERR_INVALID_CREDENTIAL_ID = 101;
const ERR_CREDENTIAL_NOT_FOUND = 102;
const ERR_ALREADY_REVOKED = 103;
const ERR_MAX_REVOCATIONS = 123;

interface Revocation {
  issuer: string;
  reason: string;
  timestamp: number;
  proof: Uint8Array;
  revokedBy: string;
}

interface IssuerStats {
  total: number;
  active: number;
}

type Result<T, E = number> = { ok: boolean; value: T | E };

class RevocationRegistryMock {
  state: {
    authorityContract: string | null;
    maxRevocationsPerIssuer: number;
    revocations: Map<number, Revocation>;
    revocationIndex: Map<string, number[]>;
    issuerStats: Map<string, IssuerStats>;
  } = {
    authorityContract: null,
    maxRevocationsPerIssuer: 100,
    revocations: new Map(),
    revocationIndex: new Map(),
    issuerStats: new Map(),
  };
  blockHeight: number = 100;
  caller: string = "ST1ISSUER";

  constructor() {
    this.reset();
  }

  reset() {
    this.state = {
      authorityContract: null,
      maxRevocationsPerIssuer: 100,
      revocations: new Map(),
      revocationIndex: new Map(),
      issuerStats: new Map(),
    };
    this.blockHeight = 100;
    this.caller = "ST1ISSUER";
  }

  setAuthorityContract(contract: string): Result<boolean> {
    if (this.caller !== contract)
      return { ok: false, value: ERR_NOT_AUTHORIZED };
    this.state.authorityContract = contract;
    return { ok: true, value: true };
  }

  setMaxRevocations(newMax: number): Result<boolean> {
    if (!this.state.authorityContract)
      return { ok: false, value: ERR_NOT_AUTHORIZED };
    if (newMax <= 0 || newMax > 500)
      return { ok: false, value: ERR_INVALID_UPDATE };
    this.state.maxRevocationsPerIssuer = newMax;
    return { ok: true, value: true };
  }

  revokeCredential(
    credentialId: number,
    reason: string,
    proof: Uint8Array
  ): Result<boolean> {
    if (credentialId <= 0)
      return { ok: false, value: ERR_INVALID_CREDENTIAL_ID };
    if (!reason || reason.length === 0 || reason.length > 256)
      return { ok: false, value: ERR_INVALID_REASON };
    if (proof.length !== 64) return { ok: false, value: ERR_INVALID_PROOF };
    if (this.state.revocations.has(credentialId))
      return { ok: false, value: ERR_ALREADY_REVOKED };
    const ids = this.state.revocationIndex.get(this.caller) || [];
    if (ids.length >= this.state.maxRevocationsPerIssuer)
      return { ok: false, value: ERR_MAX_REVOCATIONS };
    const revocation: Revocation = {
      issuer: this.caller,
      reason,
      timestamp: this.blockHeight,
      proof,
      revokedBy: this.caller,
    };
    this.state.revocations.set(credentialId, revocation);
    this.state.revocationIndex.set(this.caller, [...ids, credentialId]);
    const stats = this.state.issuerStats.get(this.caller) || {
      total: 0,
      active: 0,
    };
    this.state.issuerStats.set(this.caller, {
      total: stats.total + 1,
      active: stats.active + 1,
    });
    return { ok: true, value: true };
  }

  updateRevocation(
    credentialId: number,
    newReason: string,
    newProof: Uint8Array
  ): Result<boolean> {
    const revocation = this.state.revocations.get(credentialId);
    if (!revocation) return { ok: false, value: ERR_CREDENTIAL_NOT_FOUND };
    if (revocation.issuer !== this.caller)
      return { ok: false, value: ERR_NOT_AUTHORIZED };
    if (!newReason || newReason.length === 0 || newReason.length > 256)
      return { ok: false, value: ERR_INVALID_REASON };
    if (newProof.length !== 64) return { ok: false, value: ERR_INVALID_PROOF };
    this.state.revocations.set(credentialId, {
      ...revocation,
      reason: newReason,
      proof: newProof,
    });
    return { ok: true, value: true };
  }

  unrevokeCredential(credentialId: number): Result<boolean> {
    const revocation = this.state.revocations.get(credentialId);
    if (!revocation) return { ok: false, value: ERR_CREDENTIAL_NOT_FOUND };
    if (revocation.issuer !== this.caller)
      return { ok: false, value: ERR_NOT_AUTHORIZED };
    this.state.revocations.delete(credentialId);
    const stats = this.state.issuerStats.get(this.caller)!;
    this.state.issuerStats.set(this.caller, {
      total: stats.total,
      active: stats.active - 1,
    });
    return { ok: true, value: true };
  }

  isRevoked(credentialId: number): boolean {
    return this.state.revocations.has(credentialId);
  }

  getRevocation(credentialId: number): Revocation | undefined {
    return this.state.revocations.get(credentialId);
  }

  getRevocationIds(issuer: string): number[] {
    return this.state.revocationIndex.get(issuer) || [];
  }

  getIssuerStats(issuer: string): IssuerStats {
    return this.state.issuerStats.get(issuer) || { total: 0, active: 0 };
  }

  getRevocationByIndex(issuer: string, index: number): Result<number> {
    const ids = this.state.revocationIndex.get(issuer) || [];
    if (index >= 100 || index >= ids.length)
      return { ok: false, value: ERR_INVALID_INDEX };
    return { ok: true, value: ids[index] };
  }

  checkRevocationExistence(credentialId: number): Result<boolean> {
    return { ok: true, value: this.state.revocations.has(credentialId) };
  }
}

describe("RevocationRegistry", () => {
  let contract: RevocationRegistryMock;

  beforeEach(() => {
    contract = new RevocationRegistryMock();
    contract.reset();
  });

  it("revokes credential successfully", () => {
    const proof = new Uint8Array(64).fill(1);
    const result = contract.revokeCredential(1, "License expired", proof);
    expect(result.ok).toBe(true);
    expect(contract.isRevoked(1)).toBe(true);
    expect(contract.getIssuerStats("ST1ISSUER").total).toBe(1);
    expect(contract.getIssuerStats("ST1ISSUER").active).toBe(1);
  });

  it("rejects duplicate revocation", () => {
    const proof = new Uint8Array(64).fill(1);
    contract.revokeCredential(1, "Expired", proof);
    const result = contract.revokeCredential(1, "Duplicate", proof);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_ALREADY_REVOKED);
  });

  it("updates revocation reason and proof", () => {
    const proof1 = new Uint8Array(64).fill(1);
    const proof2 = new Uint8Array(64).fill(2);
    contract.revokeCredential(1, "Old reason", proof1);
    const result = contract.updateRevocation(1, "New reason", proof2);
    expect(result.ok).toBe(true);
    const rev = contract.getRevocation(1);
    expect(rev?.reason).toBe("New reason");
    expect(rev?.proof).toEqual(proof2);
  });

  it("unrevokes credential", () => {
    const proof = new Uint8Array(64).fill(1);
    contract.revokeCredential(1, "Temporary", proof);
    const result = contract.unrevokeCredential(1);
    expect(result.ok).toBe(true);
    expect(contract.isRevoked(1)).toBe(false);
    expect(contract.getIssuerStats("ST1ISSUER").active).toBe(0);
  });

  it("enforces max revocations per issuer", () => {
    contract.state.maxRevocationsPerIssuer = 1;
    const proof = new Uint8Array(64).fill(1);
    contract.revokeCredential(1, "First", proof);
    const result = contract.revokeCredential(2, "Second", proof);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_MAX_REVOCATIONS);
  });

  it("gets revocation by index", () => {
    const proof = new Uint8Array(64).fill(1);
    contract.revokeCredential(1, "One", proof);
    contract.revokeCredential(2, "Two", proof);
    const result = contract.getRevocationByIndex("ST1ISSUER", 1);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(2);
  });

  it("checks revocation existence", () => {
    const proof = new Uint8Array(64).fill(1);
    contract.revokeCredential(1, "Test", proof);
    const result = contract.checkRevocationExistence(1);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
  });

  it("sets authority contract", () => {
    contract.caller = "STADMIN";
    const result = contract.setAuthorityContract("STADMIN");
    expect(result.ok).toBe(true);
    expect(contract.state.authorityContract).toBe("STADMIN");
  });

  it("sets max revocations", () => {
    contract.state.authorityContract = "STADMIN";
    contract.caller = "STADMIN";
    const result = contract.setMaxRevocations(200);
    expect(result.ok).toBe(true);
    expect(contract.state.maxRevocationsPerIssuer).toBe(200);
  });
});
