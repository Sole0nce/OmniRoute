import { NextResponse } from "next/server";
import { getAuditRequestContext, logAuditEvent } from "@/lib/compliance/index";
import { cookies } from "next/headers";

export const logoutRouteInternals = {
  getCookieStore: cookies,
};

export async function POST(request) {
  const auditContext = getAuditRequestContext(request);
  const cookieStore = await logoutRouteInternals.getCookieStore();
  cookieStore.delete("auth_token");
  // OIDC handshake cookies — short-lived, but clear them on explicit logout too.
  cookieStore.delete("oidc_state");
  cookieStore.delete("oidc_nonce");
  cookieStore.delete("oidc_code_verifier");
  logAuditEvent({
    action: "auth.logout.success",
    actor: "admin",
    target: "dashboard-auth",
    resourceType: "auth_session",
    status: "success",
    ipAddress: auditContext.ipAddress || undefined,
    requestId: auditContext.requestId,
  });
  return NextResponse.json({ success: true });
}
