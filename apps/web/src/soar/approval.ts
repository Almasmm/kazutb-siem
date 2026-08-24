import { ApiError } from "../api/client";
import type { ApprovalDecision, ApprovalStatus, SOARApprovalDecisionRequest } from "../api/types";

export function buildApprovalDecisionRequest(
  decision: ApprovalDecision,
  reason: string,
  version: number,
): SOARApprovalDecisionRequest {
  const normalizedReason = reason.trim();
  if (normalizedReason.length < 2 || normalizedReason.length > 2000) {
    throw new Error("approval reason must contain 2-2000 characters");
  }
  if (!Number.isInteger(version) || version < 1) {
    throw new Error("approval version must be a positive integer");
  }
  return { decision, reason: normalizedReason, version };
}

export function approvalSubmitDisabled(reason: string, pending: boolean): boolean {
  const length = reason.trim().length;
  return pending || length < 2 || length > 2000;
}

export function createApprovalSubmissionGate() {
  let acquired = false;
  return {
    tryAcquire(): boolean {
      if (acquired) return false;
      acquired = true;
      return true;
    },
    release(): void {
      acquired = false;
    },
  };
}

export function approvalResultMessageKey(status: ApprovalStatus): string {
  if (status === "APPROVED") return "soarPage.approvedSuccess";
  if (status === "REJECTED") return "soarPage.rejectedSuccess";
  return "soarPage.decisionRecorded";
}

export function approvalErrorMessageKey(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 403) return "soarPage.permissionDenied";
    if (error.status === 409 || error.status === 412) return "soarPage.staleVersion";
    if (error.status === 422) return "soarPage.validationError";
  }
  return "soarPage.decisionError";
}

export function isApprovalVersionConflict(error: unknown): boolean {
  return error instanceof ApiError && (error.status === 409 || error.status === 412);
}
