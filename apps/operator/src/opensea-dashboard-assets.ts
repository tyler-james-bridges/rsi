export const OPENSEA_OPERATOR_DASHBOARD_HTML = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <meta name="color-scheme" content="dark">
    <title>RSI OpenSea Canary</title>
    <link rel="stylesheet" href="/operator.css">
  </head>
  <body>
    <header class="masthead">
      <div>
        <p class="eyebrow">Recursive Self-Improvement</p>
        <h1>OpenSea read canary</h1>
      </div>
      <div class="connection" aria-live="polite">
        <span class="pulse" aria-hidden="true"></span>
        <span id="connection-status">Connecting</span>
      </div>
    </header>

    <main>
      <section class="hero" aria-labelledby="overview-title">
        <div>
          <p class="eyebrow">Local, non-payment control plane</p>
          <h2 id="overview-title">One fixed Base trending read</h2>
          <p class="lede">
            This console can authorize one exact OpenSea collections request only while the
            persisted runtime is in RESEARCH. It cannot pay a 402 response, follow pagination,
            place an order, sign, approve, or submit a transaction.
          </p>
        </div>
        <button id="refresh" class="secondary" type="button">Refresh status</button>
      </section>

      <section class="grid" aria-label="OpenSea canary status">
        <article class="panel span-two">
          <div class="panel-heading">
            <div>
              <p class="eyebrow">Fail-closed runtime</p>
              <h2>Mode and authority</h2>
            </div>
            <span id="runtime-mode" class="badge neutral" aria-live="polite">Checking</span>
          </div>
          <dl class="metric-grid">
            <div class="metric"><dt>Revision</dt><dd id="runtime-revision">—</dd></div>
            <div class="metric"><dt>Changed at</dt><dd id="runtime-changed">—</dd></div>
            <div class="metric"><dt>Runtime storage</dt><dd>PERSISTED</dd></div>
            <div class="metric"><dt>Financial authority</dt><dd>NONE</dd></div>
          </dl>
          <div class="actions" aria-label="Runtime controls">
            <button id="runtime-research" type="button" disabled>Enter RESEARCH</button>
            <button id="runtime-stop" class="danger" type="button">STOP</button>
          </div>
          <p id="runtime-message" class="message" aria-live="polite">
            STOP remains available without a successful status read.
          </p>
        </article>

        <article class="panel span-two">
          <div class="panel-heading">
            <div>
              <p class="eyebrow">Stage 1 · one-shot read</p>
              <h2>OpenSea Base trending collections</h2>
            </div>
            <span id="canary-status" class="badge neutral" aria-live="polite">Checking</span>
          </div>
          <p class="help">
            Raw provider bytes are encrypted before validation and deleted before a public
            completion receipt is emitted. This dashboard receives counts and bounded status
            only—never collection names, slugs, addresses, raw metadata, credentials, capture
            identifiers, or private provenance.
          </p>
          <dl class="metric-grid">
            <div class="metric"><dt>Plan ID</dt><dd id="canary-plan-id">—</dd></div>
            <div class="metric"><dt>Credential</dt><dd id="canary-credential">—</dd></div>
            <div class="metric"><dt>Request / results cap</dt><dd id="canary-bounds">1 / 10</dd></div>
            <div class="metric"><dt>Provider charge</dt><dd>UNKNOWN</dd></div>
            <div class="metric"><dt>Ledger reservation</dt><dd id="canary-ledger-reserve">—</dd></div>
            <div class="metric"><dt>Last outcome</dt><dd id="canary-last-outcome">—</dd></div>
            <div class="metric"><dt>Collections accepted</dt><dd id="canary-last-count">—</dd></div>
            <div class="metric"><dt>Completed at</dt><dd id="canary-last-completed">—</dd></div>
          </dl>
          <div class="stack">
            <button id="canary-refresh-credential" class="secondary" type="button">
              Check Keychain status
            </button>
            <label>
              Type the exact plan ID
              <input id="canary-plan-ack" autocomplete="off" inputmode="text" spellcheck="false"
                placeholder="opensea-base-trending-collections-v1">
            </label>
            <label class="check-row">
              <input id="canary-one-request-ack" type="checkbox">
              <span>I authorize exactly one GET with no retry, redirect, or pagination.</span>
            </label>
            <label class="check-row">
              <input id="canary-no-payment-ack" type="checkbox">
              <span>I understand this canary cannot pay; HTTP 402 fails closed.</span>
            </label>
            <button id="canary-run" type="button" disabled>Run one-shot OpenSea read</button>
          </div>
          <p id="canary-message" class="message" aria-live="polite"></p>
        </article>

        <article class="panel span-two">
          <div class="panel-heading">
            <div><p class="eyebrow">Content-free audit</p><h2>Recent runtime events</h2></div>
            <span id="events-state" class="badge neutral">Checking</span>
          </div>
          <ol id="events" class="event-list"><li>No events loaded.</li></ol>
        </article>
      </section>
    </main>
    <script type="module" src="/operator.js"></script>
  </body>
</html>`;

export const OPENSEA_OPERATOR_DASHBOARD_CSS = `
:root {
  color-scheme: dark;
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  background: #07100d;
  color: #edf8f3;
  font-synthesis: none;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  min-height: 100vh;
  background:
    radial-gradient(circle at 10% 0%, rgba(27, 129, 95, .2), transparent 32rem),
    linear-gradient(160deg, #07100d 0%, #091612 52%, #07100d 100%);
}
.masthead, main { width: min(1120px, calc(100% - 2rem)); margin-inline: auto; }
.masthead { display: flex; justify-content: space-between; gap: 1rem; align-items: center; padding: 2rem 0 1rem; }
h1, h2, p { margin-top: 0; }
h1 { margin-bottom: 0; font-size: clamp(1.7rem, 4vw, 2.6rem); letter-spacing: -.04em; }
h2 { margin-bottom: .55rem; font-size: 1.2rem; }
.eyebrow { margin-bottom: .45rem; color: #67d9ae; font-size: .72rem; font-weight: 800; letter-spacing: .12em; text-transform: uppercase; }
.connection { display: flex; gap: .55rem; align-items: center; color: #a9c3b9; font-size: .85rem; }
.pulse { width: .62rem; height: .62rem; border-radius: 999px; background: #e3b95c; box-shadow: 0 0 0 .25rem rgba(227,185,92,.12); }
.connection.online .pulse { background: #57d5a3; box-shadow: 0 0 0 .25rem rgba(87,213,163,.12); }
.connection.offline .pulse { background: #ef7777; box-shadow: 0 0 0 .25rem rgba(239,119,119,.12); }
.hero, .panel { border: 1px solid rgba(148, 205, 183, .15); background: rgba(10, 25, 20, .82); box-shadow: 0 1.5rem 4rem rgba(0,0,0,.2); }
.hero { display: flex; justify-content: space-between; align-items: end; gap: 2rem; padding: 1.4rem; border-radius: 1.1rem; }
.lede, .help { max-width: 78ch; margin-bottom: 0; color: #a9c3b9; line-height: 1.55; }
.grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 1rem; padding: 1rem 0 3rem; }
.panel { padding: 1.25rem; border-radius: 1rem; min-width: 0; }
.span-two { grid-column: span 2; }
.panel-heading { display: flex; justify-content: space-between; gap: 1rem; align-items: start; }
.badge { display: inline-flex; padding: .3rem .65rem; border-radius: 999px; font-size: .73rem; font-weight: 800; text-transform: uppercase; }
.badge.neutral { color: #d5dfdb; background: rgba(181,195,190,.12); }
.badge.good { color: #7ce6bd; background: rgba(67,180,138,.14); }
.badge.bad { color: #ff9a9a; background: rgba(220,84,84,.14); }
.metric-grid { display: grid; grid-template-columns: repeat(4, minmax(0,1fr)); gap: .7rem; margin: 1rem 0 0; }
.metric { min-width: 0; padding: .8rem; border: 1px solid rgba(148,205,183,.11); border-radius: .75rem; background: rgba(255,255,255,.025); }
dt { color: #82a598; font-size: .72rem; text-transform: uppercase; letter-spacing: .06em; }
dd { margin: .3rem 0 0; overflow-wrap: anywhere; font: 700 .88rem ui-monospace, SFMono-Regular, Menlo, monospace; }
.actions { display: flex; flex-wrap: wrap; gap: .65rem; margin-top: 1rem; }
.stack { display: grid; gap: .8rem; margin-top: 1.1rem; }
label { display: grid; gap: .45rem; color: #c8ddd5; font-size: .86rem; }
.check-row { display: flex; align-items: start; gap: .6rem; }
input[type="text"] { width: 100%; padding: .72rem .8rem; color: #edf8f3; background: #06100c; border: 1px solid #315e4d; border-radius: .55rem; font: inherit; }
input[type="checkbox"] { margin-top: .18rem; accent-color: #54d1a0; }
button { border: 0; border-radius: .6rem; padding: .7rem 1rem; color: #042017; background: #65ddb0; font-weight: 800; cursor: pointer; }
button.secondary { color: #d8eee6; background: rgba(255,255,255,.08); }
button.danger { color: #fff; background: #b53f4d; }
button:disabled { opacity: .42; cursor: not-allowed; }
.message { min-height: 1.3rem; margin: .85rem 0 0; color: #a9c3b9; }
.message.error { color: #ff9a9a; }
.event-list { display: grid; gap: .55rem; padding-left: 1.3rem; color: #bcd2c9; }
.event-list li { padding: .65rem .75rem; border-radius: .6rem; background: rgba(255,255,255,.025); overflow-wrap: anywhere; }
@media (max-width: 760px) {
  .hero { align-items: stretch; flex-direction: column; }
  .grid { grid-template-columns: 1fr; }
  .span-two { grid-column: span 1; }
  .metric-grid { grid-template-columns: repeat(2, minmax(0,1fr)); }
}
@media (max-width: 470px) {
  .masthead { align-items: start; flex-direction: column; }
  .metric-grid { grid-template-columns: 1fr; }
}
`;

export const OPENSEA_OPERATOR_DASHBOARD_JS = `
(() => {
  "use strict";
  const byId = (id) => document.getElementById(id);
  let runtimeSnapshot = null;
  let canaryProjection = null;
  let pendingRuntime = false;
  let pendingCanary = false;
  let pendingCredentialRefresh = false;
  let runtimeActions = new Set();

  function setConnection(state, label) {
    const wrapper = byId("connection-status").parentElement;
    wrapper.className = "connection " + state;
    byId("connection-status").textContent = label;
  }

  async function requestJson(path, init) {
    const response = await fetch(path, { cache: "no-store", credentials: "same-origin", ...init });
    const body = await response.json();
    if (!response.ok) {
      const message = body && body.error && typeof body.error.message === "string"
        ? body.error.message
        : "The local request did not complete.";
      const error = new Error(message);
      error.code = body && body.error && typeof body.error.code === "string"
        ? body.error.code
        : "request_failed";
      throw error;
    }
    return body;
  }

  function updateButtons() {
    byId("runtime-research").disabled = pendingRuntime || !runtimeSnapshot ||
      !runtimeActions.has("runtime-enter-research") || runtimeSnapshot.mode === "RESEARCH";
    // STOP is independent of status and capability reads.
    byId("runtime-stop").disabled = false;
    byId("canary-refresh-credential").disabled = pendingCredentialRefresh || pendingCanary;
    const plan = canaryProjection && canaryProjection.plan;
    byId("canary-run").disabled = pendingCanary || !runtimeSnapshot ||
      runtimeSnapshot.mode !== "RESEARCH" || !canaryProjection ||
      canaryProjection.status !== "ready" || canaryProjection.credentialStatus !== "configured" ||
      !plan || byId("canary-plan-ack").value.trim() !== plan.planId ||
      !byId("canary-one-request-ack").checked || !byId("canary-no-payment-ack").checked;
  }

  function renderRuntime(snapshot) {
    runtimeSnapshot = snapshot;
    const badge = byId("runtime-mode");
    badge.textContent = snapshot.mode;
    badge.className = snapshot.mode === "STOPPED" ? "badge neutral" : "badge good";
    byId("runtime-revision").textContent = String(snapshot.revision);
    byId("runtime-changed").textContent = snapshot.modeChangedAt;
    updateButtons();
  }

  function clearRuntime(message) {
    runtimeSnapshot = null;
    const badge = byId("runtime-mode");
    badge.textContent = "Unavailable";
    badge.className = "badge bad";
    byId("runtime-revision").textContent = "—";
    byId("runtime-changed").textContent = "—";
    byId("runtime-message").textContent = message;
    byId("runtime-message").className = "message error";
    updateButtons();
  }

  function renderCanary(projection) {
    canaryProjection = projection;
    const plan = projection.plan;
    const receipt = projection.lastReceipt;
    const badge = byId("canary-status");
    badge.textContent = projection.status;
    badge.className = projection.status === "ready" || projection.status === "completed"
      ? "badge good"
      : projection.status === "failed" || projection.status === "interrupted"
        ? "badge bad"
        : "badge neutral";
    byId("canary-plan-id").textContent = plan.planId;
    byId("canary-credential").textContent = projection.credentialStatus;
    byId("canary-bounds").textContent = String(plan.maximumRequests) + " / " + String(plan.maximumResults);
    byId("canary-ledger-reserve").textContent = plan.ledgerReserveUsdMicros + " µUSD internal floor";
    byId("canary-last-outcome").textContent = receipt ? receipt.outcome : "—";
    byId("canary-last-count").textContent = receipt && typeof receipt.collectionCount === "number"
      ? String(receipt.collectionCount)
      : "—";
    byId("canary-last-completed").textContent = receipt ? receipt.completedAt : "—";
    updateButtons();
  }

  function clearCanary() {
    canaryProjection = null;
    const badge = byId("canary-status");
    badge.textContent = "Unavailable";
    badge.className = "badge neutral";
    byId("canary-plan-id").textContent = "opensea-base-trending-collections-v1";
    byId("canary-credential").textContent = "unknown";
    byId("canary-ledger-reserve").textContent = "1 µUSD internal floor";
    byId("canary-last-outcome").textContent = "—";
    byId("canary-last-count").textContent = "—";
    byId("canary-last-completed").textContent = "—";
    updateButtons();
  }

  function renderEvents(events) {
    const list = byId("events");
    list.replaceChildren();
    if (!Array.isArray(events) || events.length === 0) {
      const item = document.createElement("li");
      item.textContent = "No recent content-free runtime events.";
      list.append(item);
    } else {
      for (const event of events) {
        const item = document.createElement("li");
        const type = event && typeof event.type === "string" ? event.type : "event";
        const sequence = event && Number.isSafeInteger(event.sequence) ? String(event.sequence) : "?";
        item.textContent = sequence + " · " + type;
        list.append(item);
      }
    }
    byId("events-state").textContent = "Loaded";
    byId("events-state").className = "badge good";
  }

  async function refresh() {
    const [runtime, canary, events, capabilities] = await Promise.allSettled([
      requestJson("/api/runtime"),
      requestJson("/api/opensea-read-canary"),
      requestJson("/api/events?limit=12"),
      requestJson("/api/control/capabilities"),
    ]);
    if (runtime.status === "fulfilled") renderRuntime(runtime.value.runtime);
    else clearRuntime("Runtime status could not be read. STOP remains available.");
    if (canary.status === "fulfilled") renderCanary(canary.value.openSeaReadCanary);
    else clearCanary();
    if (events.status === "fulfilled") renderEvents(events.value.events);
    else {
      byId("events-state").textContent = "Unavailable";
      byId("events-state").className = "badge bad";
    }
    runtimeActions = new Set(capabilities.status === "fulfilled"
      ? capabilities.value.controls.runtime.actions
      : []);
    updateButtons();
    const successful = [runtime, canary, events, capabilities].filter((value) => value.status === "fulfilled").length;
    setConnection(successful === 0 ? "offline" : "online", successful === 4
      ? "Local connection ready"
      : successful === 0 ? "Local connection unavailable" : "Local connection partially available");
  }

  async function runtimeControl(action) {
    if (action !== "runtime-stop" && !runtimeActions.has(action)) return;
    pendingRuntime = true;
    updateButtons();
    const message = byId("runtime-message");
    message.className = "message";
    message.textContent = action === "runtime-stop" ? "Persisting STOP…" : "Entering RESEARCH…";
    try {
      const command = action === "runtime-stop"
        ? { action, requestId: crypto.randomUUID() }
        : {
            action,
            expectedMode: runtimeSnapshot.mode,
            expectedRevision: runtimeSnapshot.revision,
            requestId: crypto.randomUUID(),
          };
      const body = await requestJson("/api/control", {
        method: "POST",
        headers: { "content-type": "application/json", "x-rsi-operator-request": "1" },
        body: JSON.stringify(command),
      });
      renderRuntime(body.result);
      message.textContent = action === "runtime-stop" ? "STOPPED is persisted." : "RESEARCH is persisted.";
    } catch (error) {
      message.textContent = error instanceof Error ? error.message : "Runtime control failed.";
      message.className = "message error";
    } finally {
      pendingRuntime = false;
      updateButtons();
      void refresh();
    }
  }

  async function runCanary() {
    if (byId("canary-run").disabled || !runtimeSnapshot || !canaryProjection) return;
    const plan = canaryProjection.plan;
    pendingCanary = true;
    updateButtons();
    const message = byId("canary-message");
    message.className = "message";
    message.textContent = "Running one fixed, non-payment request…";
    try {
      const body = await requestJson("/api/opensea-read-canary/run", {
        method: "POST",
        headers: { "content-type": "application/json", "x-rsi-operator-request": "1" },
        body: JSON.stringify({
          schemaVersion: 1,
          planId: plan.planId,
          expectedRuntimeRevision: runtimeSnapshot.revision,
          requestId: crypto.randomUUID(),
          typedPlanIdAcknowledgement: byId("canary-plan-ack").value.trim(),
          oneRequestAcknowledgement: byId("canary-one-request-ack").checked,
          ledgerReserveUsdMicrosAcknowledgement: plan.ledgerReserveUsdMicros,
          nonPaymentReadAcknowledgement: byId("canary-no-payment-ack").checked,
        }),
      });
      message.textContent = "Canary completed: " + body.result.outcome + ".";
      message.className = body.result.outcome === "accepted" || body.result.outcome === "empty"
        ? "message"
        : "message error";
    } catch (error) {
      message.textContent = error instanceof Error ? error.message : "OpenSea read canary failed.";
      message.className = "message error";
    } finally {
      pendingCanary = false;
      updateButtons();
      void refresh();
    }
  }

  async function refreshCredentialStatus() {
    if (pendingCredentialRefresh) return;
    pendingCredentialRefresh = true;
    updateButtons();
    const message = byId("canary-message");
    message.className = "message";
    message.textContent = "Checking Keychain item presence without reading its value…";
    try {
      const body = await requestJson("/api/opensea-read-canary/refresh-credential-status", {
        method: "POST",
        headers: { "x-rsi-operator-request": "1" },
      });
      renderCanary(body.openSeaReadCanary);
      message.textContent = "Credential status refreshed; no credential value was read.";
    } catch (error) {
      message.textContent = error instanceof Error ? error.message : "Credential status refresh failed.";
      message.className = "message error";
    } finally {
      pendingCredentialRefresh = false;
      updateButtons();
    }
  }

  byId("refresh").addEventListener("click", refresh);
  byId("runtime-research").addEventListener("click", () => runtimeControl("runtime-enter-research"));
  byId("runtime-stop").addEventListener("click", () => runtimeControl("runtime-stop"));
  byId("canary-refresh-credential").addEventListener("click", refreshCredentialStatus);
  byId("canary-plan-ack").addEventListener("input", updateButtons);
  byId("canary-one-request-ack").addEventListener("change", updateButtons);
  byId("canary-no-payment-ack").addEventListener("change", updateButtons);
  byId("canary-run").addEventListener("click", runCanary);
  updateButtons();
  void refresh();
})();
`;
