import { describe, expect, it } from "vitest";
import { ApiError } from "../api/client";
import { ApprovalDecision } from "../api/types";
import { en } from "../i18n/locales/en";
import { kk } from "../i18n/locales/kk";
import { ru } from "../i18n/locales/ru";
import { approvalErrorMessageKey, approvalResultMessageKey, approvalSubmitDisabled, buildApprovalDecisionRequest, createApprovalSubmissionGate } from "./approval";

describe("SOAR approval contract", () => {
  it("exposes exactly APPROVE and REJECT as request commands", () => {
    expect(Object.values(ApprovalDecision)).toEqual(["APPROVE", "REJECT"]);
    expect(Object.values(ApprovalDecision)).not.toContain("APPROVED");
    expect(Object.values(ApprovalDecision)).not.toContain("REJECTED");
  });

  it("builds canonical payloads independently from localized labels", () => {
    expect(buildApprovalDecisionRequest(ApprovalDecision.APPROVE, "  Reviewed  ", 4)).toEqual({ decision: "APPROVE", reason: "Reviewed", version: 4 });
    expect(buildApprovalDecisionRequest(ApprovalDecision.REJECT, "Unsafe", 8)).toEqual({ decision: "REJECT", reason: "Unsafe", version: 8 });
  });

  it("blocks duplicate submission and invalid reject reasons", () => {
    expect(approvalSubmitDisabled("Valid reason", true)).toBe(true);
    expect(approvalSubmitDisabled("", false)).toBe(true);
    expect(() => buildApprovalDecisionRequest(ApprovalDecision.REJECT, " ", 1)).toThrow();
    const gate = createApprovalSubmissionGate();
    expect(gate.tryAcquire()).toBe(true);
    expect(gate.tryAcquire()).toBe(false);
    gate.release();
    expect(gate.tryAcquire()).toBe(true);
  });

  it("maps success, permission, validation, and stale-version states", () => {
    expect(approvalResultMessageKey("APPROVED")).toBe("soarPage.approvedSuccess");
    expect(approvalResultMessageKey("REJECTED")).toBe("soarPage.rejectedSuccess");
    expect(approvalErrorMessageKey(new ApiError(403))).toBe("soarPage.permissionDenied");
    expect(approvalErrorMessageKey(new ApiError(409))).toBe("soarPage.staleVersion");
    expect(approvalErrorMessageKey(new ApiError(422))).toBe("soarPage.validationError");
  });

  it("keeps RU, KK, and EN command and resulting-status terminology distinct", () => {
    expect(ru.common.approve).toBe("Подтвердить");
    expect(ru.status.approved).toBe("Подтверждено");
    expect(kk.common.approve).toBe("Мақұлдау");
    expect(kk.status.approved).toBe("Мақұлданды");
    expect(en.common.reject).toBe("Reject");
    expect(en.status.rejected).toBe("Rejected");
  });
});
