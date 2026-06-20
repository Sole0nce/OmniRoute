import type { RegistryEntry } from "../../shared.ts";

// Microsoft 365 Copilot (individual / Substrate BizChat) — #4042.
// DRAFT: gated on the Rule #18 live round-trip with @skyzea1. The model id is
// cosmetic (BizChat selects the model server-side per the M365 plan); the real
// transport is the SignalR/WebSocket executor `copilot-m365-web`.
export const copilot_m365_webProvider: RegistryEntry = {
  id: "copilot-m365-web",
  alias: "m365",
  format: "openai",
  executor: "copilot-m365-web",
  baseUrl: "wss://substrate.office.com/m365Copilot/Chathub",
  authType: "apikey",
  authHeader: "cookie",
  models: [{ id: "copilot-m365", name: "Microsoft 365 Copilot (individual)" }],
};
