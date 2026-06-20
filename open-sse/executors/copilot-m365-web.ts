/**
 * Microsoft 365 Copilot (individual / Substrate BizChat) web-session executor.
 *
 * Speaks Substrate BizChat over SignalR/WebSocket, translating the OpenAI chat
 * request into the `type:4` invocation captured on `m365.cloud.microsoft/chat`
 * (#4042) and the `type:1/2/3` response frames back into OpenAI SSE chunks. The
 * wire format lives in ./copilot-m365-frames.ts and is unit-tested against the
 * real capture; this file is the WebSocket transport that drives it.
 *
 * ⚠️ DRAFT — gated on the Rule #18 live round-trip with @skyzea1. Mocked frame
 * tests are necessary but not sufficient; the per-tier query params and the
 * generated session/trace ids must be confirmed against a live socket before
 * this provider ships. The opaque individual access_token is passed through
 * as-is (never parsed), so the user must paste both the token and the Chathub
 * path (`<user-oid>@<tenant-id>`) observed in their browser devtools.
 */

import { randomUUID } from "node:crypto";
import { BaseExecutor, type ExecuteInput } from "./base.ts";
import { sanitizeErrorMessage } from "../utils/error.ts";
import { FETCH_TIMEOUT_MS } from "../config/constants.ts";
import {
  encodeFrame,
  handshakeFrame,
  keepaliveFrame,
  splitFrames,
  parseFrame,
  handshakeError,
  buildChatInvocation,
  isUpdateFrame,
  isCompletionFrame,
  isLastUpdate,
  extractBotText,
  incrementalDelta,
} from "./copilot-m365-frames.ts";
import {
  M365_INDIVIDUAL_DEFAULTS,
  type M365ConnectionParams,
  newChatSessionId,
  resolveConnectionParams,
  buildWsUrl,
  redactWsUrl,
  buildPrompt,
} from "./copilot-m365-connection.ts";

type JsonRecord = Record<string, unknown>;

const KEEPALIVE_INTERVAL_MS = 15_000;

function sseChunk(model: string, delta: JsonRecord, finishReason: string | null): string {
  return (
    "data: " +
    JSON.stringify({
      id: `chatcmpl-m365-${Date.now()}`,
      object: "chat.completion.chunk",
      created: Math.floor(Date.now() / 1000),
      model,
      choices: [{ index: 0, delta, finish_reason: finishReason }],
    }) +
    "\n\n"
  );
}

export class CopilotM365WebExecutor extends BaseExecutor {
  constructor() {
    super("copilot-m365-web", {
      id: "copilot-m365-web",
      baseUrl: `wss://${M365_INDIVIDUAL_DEFAULTS.host}/m365Copilot/Chathub`,
    });
  }

  private streamChat(
    params: M365ConnectionParams,
    prompt: string,
    model: string,
    signal?: AbortSignal | null
  ): ReadableStream<Uint8Array> {
    const wsUrl = buildWsUrl(params);
    return new ReadableStream<Uint8Array>(
      {
        start: async (controller) => {
          const encoder = new TextEncoder();
          let ws: WebSocket | null = null;
          let settled = false;
          let handshaken = false;
          let emitted = "";
          let buffer = "";
          let keepaliveTimer: ReturnType<typeof setInterval> | null = null;
          let timeoutTimer: ReturnType<typeof setTimeout> | null = null;

          const cleanup = () => {
            if (keepaliveTimer) clearInterval(keepaliveTimer);
            if (timeoutTimer) clearTimeout(timeoutTimer);
            if (ws) {
              try {
                ws.close();
              } catch {
                /* ignore */
              }
              ws = null;
            }
          };

          const finish = () => {
            if (settled) return;
            settled = true;
            cleanup();
            controller.enqueue(encoder.encode(sseChunk(model, {}, "stop")));
            controller.enqueue(encoder.encode("data: [DONE]\n\n"));
            controller.close();
          };

          const abort = (reason?: string) => {
            if (settled) return;
            settled = true;
            cleanup();
            if (reason) {
              controller.enqueue(
                encoder.encode(
                  `data: ${JSON.stringify({ error: { message: sanitizeErrorMessage(reason) } })}\n\n`
                )
              );
            }
            controller.close();
          };

          signal?.addEventListener("abort", () => abort("Request aborted"), { once: true });

          const handleFrame = (frame: JsonRecord | null) => {
            if (!frame) return;
            if (!handshaken) {
              const err = handshakeError(frame);
              if (err) {
                abort(`M365 BizChat handshake failed: ${err}`);
                return;
              }
              // Empty {} ack completes the handshake.
              handshaken = true;
              ws?.send(keepaliveFrame());
              ws?.send(
                encodeFrame(
                  buildChatInvocation({ text: prompt, traceId: newChatSessionId(), sessionId: randomUUID() })
                )
              );
              keepaliveTimer = setInterval(() => {
                try {
                  ws?.send(keepaliveFrame());
                } catch {
                  /* ignore */
                }
              }, KEEPALIVE_INTERVAL_MS);
              return;
            }
            if (isUpdateFrame(frame)) {
              const text = extractBotText(frame);
              if (text != null) {
                const delta = incrementalDelta(emitted, text);
                if (delta) {
                  emitted = text;
                  controller.enqueue(encoder.encode(sseChunk(model, { content: delta }, null)));
                }
              }
              if (isLastUpdate(frame)) {
                // Wait for the type:3 completion to close; nothing to emit here.
              }
            } else if (isCompletionFrame(frame)) {
              finish();
            }
          };

          try {
            let WS = globalThis.WebSocket;
            if (!WS) {
              // @ts-ignore — ws module has no type declarations in this project
              WS = (await import("ws")).default as unknown as typeof WebSocket;
            }
            ws = new WS(wsUrl) as WebSocket;
            timeoutTimer = setTimeout(() => abort("M365 BizChat timeout"), FETCH_TIMEOUT_MS);

            ws.onopen = () => {
              try {
                ws?.send(handshakeFrame());
              } catch (err) {
                abort(err instanceof Error ? err.message : "M365 handshake send failed");
              }
            };

            ws.onmessage = (ev: MessageEvent) => {
              const data = typeof ev.data === "string" ? ev.data : String(ev.data);
              buffer += data;
              const { frames, rest } = splitFrames(buffer);
              buffer = rest;
              for (const raw of frames) handleFrame(parseFrame(raw));
            };

            ws.onerror = () => {
              // The Event carries no safe message; emit a generic, sanitized error.
              abort("M365 BizChat WebSocket error");
            };

            ws.onclose = () => {
              finish();
            };
          } catch (err) {
            abort(err instanceof Error ? err.message : "Failed to connect to M365 BizChat");
          }
        },
      },
      { highWaterMark: 16384 }
    );
  }

  async execute(input: ExecuteInput): Promise<{
    response: Response;
    url: string;
    headers: Record<string, string>;
    transformedBody: unknown;
  }> {
    const { credentials, signal, model: inputModel } = input;
    const body = input.body as JsonRecord | undefined;
    const model = inputModel || (body?.model as string) || "copilot-m365";
    const baseUrl = this.config.baseUrl || "";

    const params = resolveConnectionParams(credentials);
    if ("error" in params) {
      return {
        response: new Response(JSON.stringify({ error: { message: params.error } }), {
          status: 400,
          headers: { "Content-Type": "application/json" },
        }),
        url: baseUrl,
        headers: {},
        transformedBody: null,
      };
    }

    const prompt = buildPrompt(body);
    if (!prompt.trim()) {
      return {
        response: new Response(JSON.stringify({ error: { message: "No user message provided" } }), {
          status: 400,
          headers: { "Content-Type": "application/json" },
        }),
        url: baseUrl,
        headers: {},
        transformedBody: null,
      };
    }

    try {
      const stream = this.streamChat(params, prompt, model, signal);
      return {
        response: new Response(stream, {
          headers: {
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache",
            Connection: "keep-alive",
          },
        }),
        url: redactWsUrl(buildWsUrl(params)),
        headers: {},
        transformedBody: { tier: "individual", model },
      };
    } catch (err) {
      const msg = sanitizeErrorMessage(err instanceof Error ? err.message : "M365 BizChat error");
      return {
        response: new Response(JSON.stringify({ error: { message: msg } }), {
          status: 502,
          headers: { "Content-Type": "application/json" },
        }),
        url: baseUrl,
        headers: {},
        transformedBody: null,
      };
    }
  }
}

export default CopilotM365WebExecutor;
