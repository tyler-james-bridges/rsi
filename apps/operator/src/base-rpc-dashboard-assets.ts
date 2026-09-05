export const BASE_RPC_OPERATOR_DASHBOARD_HTML = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <meta name="color-scheme" content="dark">
    <title>RSI Base RPC Canary</title>
    <link rel="stylesheet" href="/operator.css">
  </head>
  <body>
    <header class="masthead">
      <div>
        <p class="eyebrow">Recursive Self-Improvement</p>
        <h1>Base RPC read canary</h1>
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
          <h2 id="overview-title">One fixed Base mainnet anchor read</h2>
          <p class="lede">
            This console can authorize one exact two-method read only while the persisted runtime
            is in RESEARCH. It cannot pay, retry, fall back, navigate, open a wallet, sign, approve,
            broadcast, or submit arbitrary JSON-RPC.
          </p>
        </div>
        <button id="refresh" class="secondary" type="button">Refresh status</button>
      </section>

      <section class="grid" aria-label="Base RPC canary status">
        <article class="panel">
          <div class="panel-heading">
            <div><p class="eyebrow">Fail-closed runtime</p><h2>Mode and authority</h2></div>
            <span id="runtime-mode" class="badge neutral" aria-live="polite">Checking</span>
          </div>
          <dl class="metric-grid compact">
            <div class="metric"><dt>Revision</dt><dd id="runtime-revision">—</dd></div>
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

        <article class="panel">
          <div class="panel-heading">
            <div><p class="eyebrow">Provider assertion only</p><h2>Latest verdict</h2></div>
            <span id="canary-status" class="badge neutral" aria-live="polite">Checking</span>
          </div>
          <p class="help">
            “Provider reported finalized” records only the response to the finalized block tag.
            It is not an independent finality proof. No block identifier or raw response reaches
            this dashboard.
          </p>
          <dl class="metric-grid compact">
            <div class="metric"><dt>Outcome</dt><dd id="canary-last-outcome">—</dd></div>
            <div class="metric"><dt>Freshness</dt><dd id="canary-freshness">—</dd></div>
            <div class="metric"><dt>Provider reported finalized</dt><dd id="canary-finality">—</dd></div>
            <div class="metric"><dt>Credential</dt><dd id="canary-credential">—</dd></div>
          </dl>
        </article>

        <article class="panel span-two">
          <div class="panel-heading">
            <div><p class="eyebrow">Fixed review plan</p><h2>Authorize exactly one read</h2></div>
            <span class="badge neutral">No payment · no transaction</span>
          </div>
          <dl class="metric-grid">
            <div class="metric"><dt>Plan ID</dt><dd id="canary-plan-id">—</dd></div>
            <div class="metric"><dt>Chain / tag</dt><dd id="canary-chain">—</dd></div>
            <div class="metric"><dt>Read methods</dt><dd id="canary-methods">—</dd></div>
            <div class="metric"><dt>Request / anchor cap</dt><dd id="canary-bounds">1 / 1</dd></div>
            <div class="metric"><dt>Ledger reserve</dt><dd id="canary-ledger-reserve">—</dd></div>
            <div class="metric"><dt>Actual charge</dt><dd>UNKNOWN — PROVIDER ACCOUNT</dd></div>
            <div class="metric"><dt>Automatic retry / fallback</dt><dd>0 / NONE</dd></div>
            <div class="metric"><dt>Raw evidence</dt><dd>ENCRYPTED EPHEMERAL</dd></div>
          </dl>
          <div class="stack">
            <button id="canary-refresh-credential" class="secondary" type="button">
              Check Keychain status
            </button>
            <label>
              Type the exact plan ID
              <input id="canary-plan-ack" autocomplete="off" inputmode="text" spellcheck="false"
                placeholder="base-mainnet-finalized-anchor-v1">
            </label>
            <label class="check-row">
              <input id="canary-one-request-ack" type="checkbox">
              <span>I authorize one POST containing only eth_chainId and eth_getBlockByNumber(finalized, false).</span>
            </label>
            <label class="check-row">
              <input id="canary-no-payment-ack" type="checkbox">
              <span>I understand this read has no payment authority and must fail closed instead of paying.</span>
            </label>
            <label class="check-row">
              <input id="canary-reserve-ack" type="checkbox">
              <span>I acknowledge the exact 1 µUSD internal ledger reservation.</span>
            </label>
            <label class="check-row">
              <input id="canary-no-transaction-ack" type="checkbox">
              <span>I authorize no wallet, signature, approval, transaction, or arbitrary RPC method.</span>
            </label>
            <label class="check-row">
              <input id="canary-finality-ack" type="checkbox">
              <span>I understand finalized is provider-reported and is not independent finality proof.</span>
            </label>
            <button id="canary-run" type="button" disabled>Run one-shot Base RPC read</button>
          </div>
          <p id="canary-message" class="message" aria-live="polite"></p>
        </article>
      </section>
    </main>
    <script type="module" src="/operator.js"></script>
  </body>
</html>`;

export const BASE_RPC_OPERATOR_DASHBOARD_CSS = `
:root {
  color-scheme: dark;
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  background: #07101b;
  color: #edf5ff;
  font-synthesis: none;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  min-height: 100vh;
  background:
    radial-gradient(circle at 8% 0%, rgba(59, 130, 246, .22), transparent 34rem),
    linear-gradient(155deg, #07101b 0%, #0a1728 52%, #07101b 100%);
}
.masthead, main { width: min(1120px, calc(100% - 2rem)); margin-inline: auto; }
.masthead { display: flex; justify-content: space-between; gap: 1rem; align-items: center; padding: 2rem 0 1rem; }
h1, h2, p { margin-top: 0; }
h1 { margin-bottom: 0; font-size: clamp(1.7rem, 4vw, 2.6rem); letter-spacing: -.04em; }
h2 { margin-bottom: .55rem; font-size: 1.2rem; }
.eyebrow { margin-bottom: .45rem; color: #74b3ff; font-size: .72rem; font-weight: 800; letter-spacing: .12em; text-transform: uppercase; }
.connection { display: flex; gap: .55rem; align-items: center; color: #acc1dc; font-size: .85rem; }
.pulse { width: .62rem; height: .62rem; border-radius: 999px; background: #e3b95c; box-shadow: 0 0 0 .25rem rgba(227,185,92,.12); }
.connection.online .pulse { background: #68d7ac; box-shadow: 0 0 0 .25rem rgba(104,215,172,.12); }
.connection.offline .pulse { background: #ef7777; box-shadow: 0 0 0 .25rem rgba(239,119,119,.12); }
.hero, .panel { border: 1px solid rgba(132, 177, 231, .16); background: rgba(9, 24, 42, .84); box-shadow: 0 1.5rem 4rem rgba(0,0,0,.22); }
.hero { display: flex; justify-content: space-between; align-items: end; gap: 2rem; padding: 1.4rem; border-radius: 1.1rem; }
.lede, .help { max-width: 78ch; margin-bottom: 0; color: #acc1dc; line-height: 1.55; }
.grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 1rem; padding: 1rem 0 3rem; }
.panel { padding: 1.25rem; border-radius: 1rem; min-width: 0; }
.span-two { grid-column: span 2; }
.panel-heading { display: flex; justify-content: space-between; gap: 1rem; align-items: start; }
.badge { display: inline-flex; padding: .3rem .65rem; border-radius: 999px; font-size: .73rem; font-weight: 800; text-transform: uppercase; }
.badge.neutral { color: #d8e1ed; background: rgba(181,195,214,.12); }
.badge.good { color: #86e5bf; background: rgba(67,180,138,.14); }
.badge.bad { color: #ff9a9a; background: rgba(220,84,84,.14); }
.metric-grid { display: grid; grid-template-columns: repeat(4, minmax(0,1fr)); gap: .7rem; margin: 1rem 0 0; }
.metric-grid.compact { grid-template-columns: repeat(2, minmax(0,1fr)); }
.metric { min-width: 0; padding: .8rem; border: 1px solid rgba(132,177,231,.12); border-radius: .75rem; background: rgba(255,255,255,.025); }
dt { color: #8ea8c8; font-size: .72rem; text-transform: uppercase; letter-spacing: .06em; }
dd { margin: .3rem 0 0; overflow-wrap: anywhere; font: 700 .88rem ui-monospace, SFMono-Regular, Menlo, monospace; }
.actions { display: flex; flex-wrap: wrap; gap: .65rem; margin-top: 1rem; }
.stack { display: grid; gap: .8rem; margin-top: 1.1rem; }
label { display: grid; gap: .45rem; color: #cbd9ea; font-size: .86rem; }
.check-row { display: flex; align-items: start; gap: .6rem; }
input[type="text"] { width: 100%; padding: .72rem .8rem; color: #edf5ff; background: #06101e; border: 1px solid #345f94; border-radius: .55rem; font: inherit; }
input[type="checkbox"] { margin-top: .18rem; accent-color: #68aefc; }
button { border: 0; border-radius: .6rem; padding: .7rem 1rem; color: #06172b; background: #76b8ff; font-weight: 800; cursor: pointer; }
button.secondary { color: #dceaff; background: rgba(255,255,255,.09); }
button.danger { color: #fff; background: #b53f4d; }
button:disabled { opacity: .42; cursor: not-allowed; }
.message { min-height: 1.3rem; margin: .85rem 0 0; color: #acc1dc; }
.message.error { color: #ff9a9a; }
@media (max-width: 760px) {
  .hero { align-items: stretch; flex-direction: column; }
  .grid { grid-template-columns: 1fr; }
  .span-two { grid-column: span 1; }
  .metric-grid { grid-template-columns: repeat(2, minmax(0,1fr)); }
}
@media (max-width: 470px) {
  .masthead { align-items: start; flex-direction: column; }
  .metric-grid, .metric-grid.compact { grid-template-columns: 1fr; }
}
`;

export const BASE_RPC_OPERATOR_DASHBOARD_JS = `
(() => {
  "use strict";
  const byId = (id) => document.getElementById(id);
  const METHOD_SET_ACK = "eth_chainId[]+eth_getBlockByNumber[finalized,false]";
  let runtimeSnapshot = null;
  let canaryProjection = null;
  let pendingRuntime = false;
  let pendingCanary = false;
  let canarySubmitted = false;
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
      throw new Error(message);
    }
    return body;
  }

  function updateButtons() {
    byId("runtime-research").disabled = pendingRuntime || !runtimeSnapshot ||
      !runtimeActions.has("runtime-enter-research") || runtimeSnapshot.mode === "RESEARCH";
    // Durable STOP remains independent of status, credential, and in-flight read state.
    byId("runtime-stop").disabled = false;
    byId("canary-refresh-credential").disabled = pendingCredentialRefresh || pendingCanary;
    const plan = canaryProjection && canaryProjection.plan;
    byId("canary-run").disabled = canarySubmitted || pendingCanary || !runtimeSnapshot ||
      runtimeSnapshot.mode !== "RESEARCH" || !canaryProjection ||
      canaryProjection.status !== "ready" || canaryProjection.credentialStatus !== "configured" ||
      !plan || byId("canary-plan-ack").value.trim() !== plan.planId ||
      !byId("canary-one-request-ack").checked || !byId("canary-no-payment-ack").checked ||
      !byId("canary-reserve-ack").checked || !byId("canary-no-transaction-ack").checked ||
      !byId("canary-finality-ack").checked;
  }

  function renderRuntime(snapshot) {
    runtimeSnapshot = snapshot;
    const badge = byId("runtime-mode");
    badge.textContent = snapshot.mode;
    badge.className = snapshot.mode === "STOPPED" ? "badge neutral" : "badge good";
    byId("runtime-revision").textContent = String(snapshot.revision);
    updateButtons();
  }

  function clearRuntime(message) {
    runtimeSnapshot = null;
    const badge = byId("runtime-mode");
    badge.textContent = "Unavailable";
    badge.className = "badge bad";
    byId("runtime-revision").textContent = "—";
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
    byId("canary-chain").textContent = plan.chain + " / " + plan.blockTag;
    byId("canary-methods").textContent = plan.rpcMethods.join(" + ");
    byId("canary-bounds").textContent = String(plan.maximumRequests) + " / " + String(plan.maximumAnchors);
    byId("canary-ledger-reserve").textContent = plan.ledgerReserveUsdMicros + " µUSD internal floor";
    byId("canary-last-outcome").textContent = receipt ? receipt.outcome : "—";
    byId("canary-freshness").textContent = receipt && receipt.freshnessVerdict
      ? receipt.freshnessVerdict
      : "—";
    byId("canary-finality").textContent = receipt && receipt.providerReportedFinalized === true
      ? "YES — PROVIDER ASSERTION"
      : "—";
    updateButtons();
  }

  function clearCanary() {
    canaryProjection = null;
    const badge = byId("canary-status");
    badge.textContent = "Unavailable";
    badge.className = "badge neutral";
    byId("canary-plan-id").textContent = "base-mainnet-finalized-anchor-v1";
    byId("canary-credential").textContent = "unknown";
    byId("canary-chain").textContent = "base-mainnet / finalized";
    byId("canary-methods").textContent = "eth_chainId + eth_getBlockByNumber";
    byId("canary-ledger-reserve").textContent = "1 µUSD internal floor";
    byId("canary-last-outcome").textContent = "—";
    byId("canary-freshness").textContent = "—";
    byId("canary-finality").textContent = "—";
    updateButtons();
  }

  async function refresh() {
    const [runtime, canary, capabilities] = await Promise.allSettled([
      requestJson("/api/runtime"),
      requestJson("/api/base-rpc-read-canary"),
      requestJson("/api/control/capabilities"),
    ]);
    if (runtime.status === "fulfilled") renderRuntime(runtime.value.runtime);
    else clearRuntime("Runtime status could not be read. STOP remains available.");
    if (canary.status === "fulfilled") renderCanary(canary.value.baseRpcReadCanary);
    else clearCanary();
    runtimeActions = new Set(capabilities.status === "fulfilled"
      ? capabilities.value.controls.runtime.actions
      : []);
    updateButtons();
    const successful = [runtime, canary, capabilities].filter((value) => value.status === "fulfilled").length;
    setConnection(successful === 0 ? "offline" : "online", successful === 3
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
    // A one-shot submission stays latched for this page even after the request settles.
    // The refreshed durable projection is authoritative, but it must not create a brief
    // window where the stale pre-run projection can emit a duplicate local command.
    canarySubmitted = true;
    pendingCanary = true;
    byId("canary-run").textContent = "Running one-shot read…";
    updateButtons();
    const message = byId("canary-message");
    message.className = "message";
    message.textContent = "Running one fixed, non-payment Base RPC request…";
    try {
      const body = await requestJson("/api/base-rpc-read-canary/run", {
        method: "POST",
        headers: { "content-type": "application/json", "x-rsi-operator-request": "1" },
        body: JSON.stringify({
          schemaVersion: 1,
          planId: plan.planId,
          expectedRuntimeRevision: runtimeSnapshot.revision,
          requestId: crypto.randomUUID(),
          typedPlanIdAcknowledgement: byId("canary-plan-ack").value.trim(),
          oneRequestAcknowledgement: byId("canary-one-request-ack").checked,
          nonPaymentReadAcknowledgement: byId("canary-no-payment-ack").checked,
          noTransactionAuthorityAcknowledgement: byId("canary-no-transaction-ack").checked,
          finalizedAnchorAcknowledgement: byId("canary-finality-ack").checked,
          methodSetAcknowledgement: METHOD_SET_ACK,
          ledgerReserveUsdMicrosAcknowledgement: byId("canary-reserve-ack").checked
            ? plan.ledgerReserveUsdMicros
            : "",
        }),
      });
      message.textContent = "Canary completed: " + body.result.outcome + ".";
      message.className = body.result.outcome === "accepted" ? "message" : "message error";
    } catch (error) {
      message.textContent = error instanceof Error ? error.message : "Base RPC read canary failed.";
      message.className = "message error";
    } finally {
      pendingCanary = false;
      byId("canary-run").textContent = "Run one-shot Base RPC read";
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
      const body = await requestJson("/api/base-rpc-read-canary/refresh-credential-status", {
        method: "POST",
        headers: { "x-rsi-operator-request": "1" },
      });
      renderCanary(body.baseRpcReadCanary);
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
  for (const id of [
    "canary-one-request-ack",
    "canary-no-payment-ack",
    "canary-reserve-ack",
    "canary-no-transaction-ack",
    "canary-finality-ack",
  ]) byId(id).addEventListener("change", updateButtons);
  byId("canary-run").addEventListener("click", runCanary);
  updateButtons();
  void refresh();
})();
`;
