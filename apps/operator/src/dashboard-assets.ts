export const OPERATOR_DASHBOARD_HTML = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <meta name="color-scheme" content="dark">
    <title>RSI Runtime</title>
    <link rel="stylesheet" href="/operator.css">
  </head>
  <body>
    <header class="masthead">
      <div>
        <p class="eyebrow">Recursive Self-Improvement</p>
        <h1>Runtime console</h1>
      </div>
      <div class="connection" aria-live="polite">
        <span class="pulse" aria-hidden="true"></span>
        <span id="connection-status">Connecting</span>
      </div>
    </header>

    <main>
      <section class="hero" aria-labelledby="overview-title">
        <div>
          <p class="eyebrow">Local control plane</p>
          <h2 id="overview-title">Persisted control, visible authority</h2>
          <p class="lede">
            This console is confined to this computer. Runtime modes may permit research
            and unsigned proposal persistence only. No mode grants payment, approval,
            signing, transaction, or other financial authority.
          </p>
        </div>
        <button id="refresh" class="secondary" type="button">Refresh status</button>
      </section>

      <section class="grid" aria-label="RSI runtime status">
        <article class="panel span-two runtime-panel">
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
            <div class="metric"><dt>Process</dt><dd id="runtime-process">—</dd></div>
            <div class="metric"><dt>Financial authority</dt><dd id="runtime-authority">NONE</dd></div>
          </dl>
          <div class="runtime-actions" aria-label="Runtime mode controls">
            <button id="runtime-research" data-runtime-action="runtime-enter-research" type="button" disabled>Enter research</button>
            <button id="runtime-proposals" data-runtime-action="runtime-enter-propose-only" type="button" disabled>Enable proposals</button>
            <button id="runtime-stop" data-runtime-action="runtime-stop" class="danger" type="button">STOP</button>
          </div>
          <p id="runtime-message" class="message" aria-live="polite">
            STOP remains available independently of status reads.
          </p>
          <p class="help">Always disabled: policy approval, paid reads, wallet signing, execution adapters, transaction broadcast, and external publication.</p>
        </article>

        <article class="panel span-two">
          <div class="panel-heading">
            <div>
              <p class="eyebrow">Verified projection</p>
              <h2>System summary</h2>
            </div>
            <span id="summary-state" class="badge neutral">Waiting</span>
          </div>
          <dl id="summary-cards" class="metric-grid"></dl>
          <details>
            <summary>Structured status</summary>
            <pre id="summary-json">No status loaded.</pre>
          </details>
        </article>

        <article class="panel span-two">
          <div class="panel-heading">
            <div>
              <p class="eyebrow">Content-free research ledger</p>
              <h2>Proposals and abstentions</h2>
            </div>
            <span id="research-state" class="badge neutral">Checking</span>
          </div>
          <dl class="metric-grid research-counts">
            <div class="metric"><dt>Candidates</dt><dd id="research-candidates">—</dd></div>
            <div class="metric"><dt>Abstentions</dt><dd id="research-abstentions">—</dd></div>
          </dl>
          <ol id="research-proposals" class="proposal-list">
            <li>No content-free research projection loaded.</li>
          </ol>
        </article>

        <article class="panel">
          <div class="panel-heading">
            <div>
              <p class="eyebrow">Compatibility component</p>
              <h2>Legacy session controls</h2>
            </div>
            <span id="control-state" class="badge neutral">Checking</span>
          </div>
          <p class="help">Shown only for compatibility. These controls do not change the persisted runtime mode.</p>
          <div class="stack">
            <button data-action="plan" type="button">Plan session</button>
            <label>
              Session ID
              <input id="session-id" autocomplete="off" inputmode="text" spellcheck="false"
                placeholder="xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx">
            </label>
            <label class="check-row">
              <input id="observer-only" type="checkbox">
              <span>I acknowledge that this session is observation-only.</span>
            </label>
            <button data-action="start" type="button">Start supervised session</button>
            <div class="button-row">
              <button data-action="ack-45" class="secondary" type="button">Acknowledge 45 min</button>
              <button data-action="ack-90" class="secondary" type="button">Acknowledge 90 min</button>
            </div>
            <div class="button-row">
              <button data-action="close" class="secondary" type="button">Close session</button>
              <button data-action="abort" class="danger" type="button">Stop now</button>
            </div>
          </div>
          <p id="control-message" class="message" aria-live="polite"></p>
        </article>

        <article class="panel">
          <div class="panel-heading">
            <div>
              <p class="eyebrow">Compatibility component</p>
              <h2>Legacy feedback and candidate</h2>
            </div>
          </div>
          <div class="stack">
            <label>
              Finding ID
              <input id="finding-id" autocomplete="off" spellcheck="false" placeholder="finding-id">
            </label>
            <label>
              Feedback
              <select id="feedback-label">
                <option value="useful">Useful</option>
                <option value="unclear">Unclear</option>
                <option value="noise">Noise</option>
                <option value="misleading">Misleading</option>
              </select>
            </label>
            <button data-action="label" class="secondary" type="button">Record feedback</button>
            <button data-action="prepare-candidate" class="secondary" type="button">Prepare private candidate</button>
          </div>
          <p class="help">Preparing a candidate does not publish it.</p>
        </article>

        <article class="panel span-two">
          <div class="panel-heading">
            <div>
              <p class="eyebrow">Content-free history</p>
              <h2>Recent events</h2>
            </div>
          </div>
          <ol id="events" class="event-list"><li>No events loaded.</li></ol>
        </article>
      </section>
    </main>

    <footer>
      <span>RSI Local</span>
      <span>Loopback only · no financial authority · startup enforces STOPPED</span>
    </footer>
    <script src="/operator.js" defer></script>
  </body>
</html>
`;

export const OPERATOR_DASHBOARD_CSS = `:root {
  color-scheme: dark;
  --bg: #070909;
  --panel: #101414;
  --panel-soft: #151b1a;
  --line: #29312f;
  --ink: #f2f5ef;
  --muted: #97a39d;
  --acid: #c8ff47;
  --acid-dark: #17210b;
  --warning: #ffbf69;
  --danger: #ff7a6e;
  --radius: 18px;
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}

* { box-sizing: border-box; }
body { margin: 0; min-height: 100vh; background: radial-gradient(circle at 80% 0, #17201c 0, transparent 35%), var(--bg); color: var(--ink); }
button, input, select { font: inherit; }
button { border: 1px solid var(--acid); border-radius: 999px; background: var(--acid); color: #0b0e0b; font-weight: 720; padding: .72rem 1rem; cursor: pointer; }
button:hover { filter: brightness(1.08); }
button:focus-visible, input:focus-visible, select:focus-visible, summary:focus-visible { outline: 3px solid #fff; outline-offset: 3px; }
button:disabled { cursor: not-allowed; filter: grayscale(1); opacity: .48; }
button.secondary { border-color: var(--line); background: transparent; color: var(--ink); }
button.danger { border-color: #673834; background: #2a1615; color: var(--danger); }
input, select { width: 100%; border: 1px solid var(--line); border-radius: 10px; background: #090c0c; color: var(--ink); padding: .72rem .78rem; }
label { display: grid; gap: .45rem; color: var(--muted); font-size: .86rem; }

.masthead { display: flex; align-items: center; justify-content: space-between; gap: 1rem; max-width: 1180px; margin: 0 auto; padding: 1.6rem 1.4rem 1rem; }
h1, h2, p { margin-top: 0; }
h1 { margin-bottom: 0; font-size: clamp(1.5rem, 4vw, 2.3rem); letter-spacing: -.045em; }
h2 { margin-bottom: .45rem; font-size: 1.08rem; letter-spacing: -.02em; }
.eyebrow { margin-bottom: .35rem; color: var(--acid); font-size: .7rem; font-weight: 800; letter-spacing: .14em; text-transform: uppercase; }
.connection { display: flex; align-items: center; gap: .55rem; color: var(--muted); font-size: .82rem; }
.pulse { width: .62rem; height: .62rem; border-radius: 50%; background: var(--warning); box-shadow: 0 0 0 5px #ffbf6917; }
.connection.online .pulse { background: var(--acid); box-shadow: 0 0 0 5px #c8ff4717; }
.connection.offline .pulse { background: var(--danger); box-shadow: 0 0 0 5px #ff7a6e17; }

main { max-width: 1180px; margin: 0 auto; padding: 1rem 1.4rem 3rem; }
.hero { display: flex; justify-content: space-between; align-items: end; gap: 2rem; padding: 2rem 0 1.4rem; }
.hero h2 { max-width: 780px; margin-bottom: .75rem; font-size: clamp(2rem, 6vw, 4.8rem); line-height: .96; letter-spacing: -.065em; }
.lede { max-width: 700px; margin-bottom: 0; color: var(--muted); line-height: 1.6; }
.grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 1rem; }
.panel { min-width: 0; border: 1px solid var(--line); border-radius: var(--radius); background: linear-gradient(145deg, #121716, #0e1111); padding: 1.2rem; box-shadow: 0 18px 40px #0004; }
.span-two { grid-column: 1 / -1; }
.panel-heading { display: flex; justify-content: space-between; align-items: start; gap: 1rem; }
.badge { border: 1px solid var(--line); border-radius: 999px; padding: .3rem .58rem; font-size: .72rem; white-space: nowrap; }
.badge.good { border-color: #4f691c; background: var(--acid-dark); color: var(--acid); }
.badge.bad { border-color: #673834; background: #2a1615; color: var(--danger); }
.badge.neutral { color: var(--muted); }
.metric-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: .7rem; margin: 1rem 0; }
.metric { min-width: 0; border: 1px solid var(--line); border-radius: 12px; background: var(--panel-soft); padding: .85rem; }
.metric dt { color: var(--muted); font-size: .72rem; text-transform: uppercase; letter-spacing: .06em; }
.metric dd { overflow: hidden; margin: .35rem 0 0; font-weight: 750; text-overflow: ellipsis; white-space: nowrap; }
.stack { display: grid; gap: .75rem; }
.runtime-panel { border-color: #3b4d22; }
.runtime-actions { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: .6rem; }
.button-row { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: .6rem; }
.check-row { grid-template-columns: auto 1fr; align-items: start; }
.check-row input { width: auto; margin-top: .18rem; }
.help, .message { color: var(--muted); font-size: .82rem; line-height: 1.5; }
.message { min-height: 1.3rem; margin: .8rem 0 0; }
.message.error { color: var(--danger); }
details { border-top: 1px solid var(--line); padding-top: .9rem; }
summary { cursor: pointer; color: var(--muted); }
pre { overflow: auto; max-height: 28rem; border-radius: 12px; background: #080a0a; padding: 1rem; color: #d9e1db; font: .76rem/1.55 ui-monospace, SFMono-Regular, Menlo, monospace; }
.event-list { display: grid; gap: .5rem; margin: 1rem 0 0; padding: 0; list-style: none; }
.event-list li { display: grid; grid-template-columns: minmax(9rem, .35fr) 1fr; gap: 1rem; border-top: 1px solid var(--line); padding: .72rem 0; }
.event-type { color: var(--acid); font: .74rem ui-monospace, SFMono-Regular, Menlo, monospace; }
.event-data { overflow: hidden; color: var(--muted); font: .74rem/1.5 ui-monospace, SFMono-Regular, Menlo, monospace; text-overflow: ellipsis; white-space: nowrap; }
.research-counts { grid-template-columns: repeat(2, minmax(0, 1fr)); }
.proposal-list { display: grid; gap: .8rem; margin: 1rem 0 0; padding: 0; list-style: none; }
.proposal-card { display: grid; gap: .65rem; border: 1px solid var(--line); border-radius: 12px; background: #080a0a; padding: .9rem; }
.proposal-title { display: flex; flex-wrap: wrap; justify-content: space-between; gap: .5rem; }
.proposal-asset, .proposal-detail { overflow-wrap: anywhere; color: #d9e1db; font: .76rem/1.55 ui-monospace, SFMono-Regular, Menlo, monospace; }
.proposal-detail { color: var(--muted); }
.score-grid { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: .45rem; margin: 0; }
.score-grid .metric { padding: .6rem; }
footer { display: flex; justify-content: space-between; gap: 1rem; max-width: 1180px; margin: 0 auto; border-top: 1px solid var(--line); padding: 1.3rem 1.4rem 2rem; color: var(--muted); font-size: .75rem; }

@media (max-width: 760px) {
  .masthead, .hero, footer { align-items: stretch; flex-direction: column; }
  .grid { grid-template-columns: 1fr; }
  .span-two { grid-column: auto; }
  .metric-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .runtime-actions { grid-template-columns: 1fr; }
  .score-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .event-list li { grid-template-columns: 1fr; gap: .3rem; }
}

@media (prefers-reduced-motion: reduce) { *, *::before, *::after { scroll-behavior: auto !important; } }
`;

export const OPERATOR_DASHBOARD_JS = `"use strict";
(() => {
  const byId = (id) => document.getElementById(id);
  const connection = byId("connection-status").parentElement;
  const legacyButtons = Array.from(document.querySelectorAll("button[data-action]"));
  const runtimeButtons = Array.from(document.querySelectorAll("button[data-runtime-action]"));
  let supportedLegacyActions = new Set();
  let supportedRuntimeActions = new Set();
  let runtimeSnapshot = null;
  let pendingRuntimeControls = 0;

  const text = (value) => typeof value === "string" ? value : JSON.stringify(value);
  const safeSessionId = () => byId("session-id").value.trim();

  function setConnection(state, label) {
    connection.classList.remove("online", "offline");
    connection.classList.add(state);
    byId("connection-status").textContent = label;
  }

  function legacyCommandAction(buttonAction) {
    return buttonAction === "ack-45" || buttonAction === "ack-90" ? "acknowledge" : buttonAction;
  }

  function setLegacyControls(actions) {
    supportedLegacyActions = new Set(Array.isArray(actions) ? actions : []);
    for (const button of legacyButtons) {
      button.disabled = !supportedLegacyActions.has(legacyCommandAction(button.dataset.action));
    }
    const enabled = supportedLegacyActions.size > 0;
    const badge = byId("control-state");
    badge.textContent = enabled ? "Available" : "Read only";
    badge.className = enabled ? "badge good" : "badge neutral";
  }

  function updateRuntimeButtons() {
    const mode = runtimeSnapshot && runtimeSnapshot.mode;
    const research = byId("runtime-research");
    const proposals = byId("runtime-proposals");
    research.textContent = mode === "PROPOSE_ONLY" ? "Return to research" : "Enter research";
    research.disabled = pendingRuntimeControls > 0 ||
      !supportedRuntimeActions.has("runtime-enter-research") ||
      (mode !== "STOPPED" && mode !== "PROPOSE_ONLY");
    proposals.disabled = pendingRuntimeControls > 0 ||
      !supportedRuntimeActions.has("runtime-enter-propose-only") || mode !== "RESEARCH";
    // Emergency STOP does not depend on a successful snapshot or capabilities read.
    byId("runtime-stop").disabled = false;
  }

  function setRuntimeCapabilities(actions) {
    supportedRuntimeActions = new Set(Array.isArray(actions) ? actions : []);
    updateRuntimeButtons();
  }

  function renderRuntime(snapshot) {
    runtimeSnapshot = snapshot;
    const mode = typeof snapshot.mode === "string" ? snapshot.mode : "UNAVAILABLE";
    const badge = byId("runtime-mode");
    badge.textContent = mode;
    badge.className = mode === "STOPPED" ? "badge neutral" : "badge good";
    byId("runtime-revision").textContent = String(snapshot.revision);
    byId("runtime-changed").textContent = snapshot.modeChangedAt;
    byId("runtime-process").textContent = snapshot.processInstanceId;
    byId("runtime-authority").textContent = "NONE";
    updateRuntimeButtons();
  }

  function clearRuntime(message) {
    runtimeSnapshot = null;
    const badge = byId("runtime-mode");
    badge.textContent = "Unavailable";
    badge.className = "badge bad";
    byId("runtime-revision").textContent = "—";
    byId("runtime-changed").textContent = "—";
    byId("runtime-process").textContent = "—";
    byId("runtime-authority").textContent = "NONE";
    byId("runtime-message").textContent = message;
    byId("runtime-message").className = "message error";
    updateRuntimeButtons();
  }

  function renderSummary(summary) {
    byId("summary-json").textContent = JSON.stringify(summary, null, 2);
    const root = byId("summary-cards");
    root.replaceChildren();
    const entries = summary && typeof summary === "object"
      ? Object.entries(summary).filter(([, value]) => value === null || ["string", "number", "boolean"].includes(typeof value)).slice(0, 8)
      : [];
    for (const [key, value] of entries) {
      const wrapper = document.createElement("div");
      wrapper.className = "metric";
      const term = document.createElement("dt");
      term.textContent = key.replace(/([a-z])([A-Z])/g, "$1 $2");
      const definition = document.createElement("dd");
      definition.textContent = text(value);
      wrapper.append(term, definition);
      root.append(wrapper);
    }
    const badge = byId("summary-state");
    badge.textContent = "Loaded";
    badge.className = "badge good";
  }

  function renderEvents(events) {
    const root = byId("events");
    root.replaceChildren();
    if (!Array.isArray(events) || events.length === 0) {
      const item = document.createElement("li");
      item.textContent = "No recent content-free events.";
      root.append(item);
      return;
    }
    for (const event of events) {
      const item = document.createElement("li");
      const type = document.createElement("span");
      type.className = "event-type";
      type.textContent = event && typeof event.type === "string" ? event.type : "event";
      const data = document.createElement("span");
      data.className = "event-data";
      data.textContent = JSON.stringify(event);
      item.append(type, data);
      root.append(item);
    }
  }

  function appendProposalDetail(card, label, value) {
    const detail = document.createElement("div");
    detail.className = "proposal-detail";
    detail.textContent = label + ": " + value;
    card.append(detail);
  }

  function renderResearch(projection) {
    byId("research-candidates").textContent = String(projection.candidateCount);
    byId("research-abstentions").textContent = String(projection.abstentionCount);
    const badge = byId("research-state");
    badge.textContent = "Loaded";
    badge.className = "badge good";
    const root = byId("research-proposals");
    root.replaceChildren();
    if (!Array.isArray(projection.proposals) || projection.proposals.length === 0) {
      const empty = document.createElement("li");
      empty.textContent = "No persisted proposals or abstentions.";
      root.append(empty);
      return;
    }
    for (const record of projection.proposals) {
      const proposal = record.proposal;
      const card = document.createElement("li");
      card.className = "proposal-card";
      const title = document.createElement("div");
      title.className = "proposal-title";
      const proposalId = document.createElement("strong");
      proposalId.textContent = proposal.proposalId;
      const disposition = document.createElement("span");
      disposition.className = proposal.disposition.kind === "candidate" ? "badge good" : "badge neutral";
      disposition.textContent = proposal.disposition.kind === "candidate"
        ? "candidate"
        : "abstain · " + proposal.disposition.reason;
      title.append(proposalId, disposition);
      card.append(title);

      const asset = document.createElement("div");
      asset.className = "proposal-asset";
      asset.textContent = "Asset: chain " + String(proposal.asset.chainId) +
        " · contract " + proposal.asset.address + " · token " + proposal.asset.tokenId;
      card.append(asset);
      appendProposalDetail(card, "Evidence IDs", proposal.evidenceIds.join(", "));
      appendProposalDetail(card, "Source kinds", proposal.provenance.sourceKinds.join(", "));
      appendProposalDetail(card, "Provider IDs", proposal.provenance.providerIds.join(", "));
      appendProposalDetail(card, "Independent clusters", String(proposal.provenance.independentClusterCount));
      appendProposalDetail(card, "Scam flags", proposal.flags.scam.length ? proposal.flags.scam.join(", ") : "none");
      appendProposalDetail(card, "Injection flags", proposal.flags.injection.length ? proposal.flags.injection.join(", ") : "none");
      appendProposalDetail(card, "Homograph flags", proposal.flags.homograph.length ? proposal.flags.homograph.join(", ") : "none");
      appendProposalDetail(card, "Evidence event", String(record.eventSequence) + " · " + record.eventHash);

      const scores = document.createElement("dl");
      scores.className = "score-grid";
      for (const [name, value] of Object.entries(proposal.scorecard)) {
        const metric = document.createElement("div");
        metric.className = "metric";
        const term = document.createElement("dt");
        term.textContent = name.replace(/([a-z])([A-Z])/g, "$1 $2");
        const score = document.createElement("dd");
        score.textContent = String(value);
        metric.append(term, score);
        scores.append(metric);
      }
      card.append(scores);
      root.append(card);
    }
  }

  function clearResearch() {
    byId("research-candidates").textContent = "—";
    byId("research-abstentions").textContent = "—";
    const badge = byId("research-state");
    badge.textContent = "Unavailable";
    badge.className = "badge neutral";
    const root = byId("research-proposals");
    root.replaceChildren();
    const item = document.createElement("li");
    item.textContent = "The optional content-free research projection is unavailable.";
    root.append(item);
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

  async function refresh() {
    const [runtime, research, summary, events, capabilities] = await Promise.allSettled([
      requestJson("/api/runtime"),
      requestJson("/api/research"),
      requestJson("/api/summary"),
      requestJson("/api/events?limit=12"),
      requestJson("/api/control/capabilities"),
    ]);

    if (runtime.status === "fulfilled") renderRuntime(runtime.value.runtime);
    else clearRuntime("Runtime status could not be read. STOP remains available.");

    if (research.status === "fulfilled") renderResearch(research.value.research);
    else clearResearch();

    if (summary.status === "fulfilled") renderSummary(summary.value.summary);
    else {
      byId("summary-state").textContent = "Unavailable";
      byId("summary-state").className = "badge bad";
    }

    if (events.status === "fulfilled") renderEvents(events.value.events);
    if (capabilities.status === "fulfilled") {
      const controls = capabilities.value.controls || {};
      setLegacyControls(controls.legacy && controls.legacy.enabled === true ? controls.legacy.actions : []);
      setRuntimeCapabilities(controls.runtime && controls.runtime.enabled === true ? controls.runtime.actions : []);
    } else {
      setLegacyControls([]);
      setRuntimeCapabilities([]);
    }

    const successfulReads = [runtime, research, summary, events, capabilities].filter((result) => result.status === "fulfilled").length;
    if (successfulReads === 5) setConnection("online", "Local connection ready");
    else if (successfulReads > 0) setConnection("online", "Local connection partially available");
    else setConnection("offline", "Local connection unavailable");
  }

  function legacyCommandFor(action) {
    const sessionId = safeSessionId();
    if (action === "plan") {
      const nextSessionId = crypto.randomUUID();
      byId("session-id").value = nextSessionId;
      return { action: "plan", sessionId: nextSessionId };
    }
    if (action === "start") return {
      action,
      observerOnlyAcknowledgement: byId("observer-only").checked,
      sessionId,
      typedSessionIdAcknowledgement: sessionId,
    };
    if (action === "ack-45" || action === "ack-90") return {
      action: "acknowledge",
      checkpoint: action === "ack-45" ? "minute-45" : "minute-90",
      sessionId,
    };
    if (action === "abort" || action === "close") return { action, sessionId };
    const findingId = byId("finding-id").value.trim();
    if (action === "label") return {
      action,
      findingId,
      label: byId("feedback-label").value,
    };
    return { action: "prepare-candidate", findingId };
  }

  async function runLegacyControl(action) {
    if (!supportedLegacyActions.has(legacyCommandAction(action))) return;
    const message = byId("control-message");
    message.className = "message";
    message.textContent = "Working locally…";
    for (const button of legacyButtons) button.disabled = true;
    try {
      const body = await requestJson("/api/control", {
        method: "POST",
        headers: { "content-type": "application/json", "x-rsi-operator-request": "1" },
        body: JSON.stringify(legacyCommandFor(action)),
      });
      const result = body.result || {};
      if (typeof result.sessionId === "string") byId("session-id").value = result.sessionId;
      message.textContent = "Local compatibility action completed.";
      await refresh();
    } catch (error) {
      message.textContent = error instanceof Error ? error.message : "Local action failed.";
      message.className = "message error";
    } finally {
      setLegacyControls([...supportedLegacyActions]);
    }
  }

  function runtimeCommand(action) {
    const requestId = crypto.randomUUID();
    if (action === "runtime-stop") return { action, requestId };
    if (!runtimeSnapshot) throw new Error("Runtime status must be refreshed before a transition.");
    return {
      action,
      expectedMode: runtimeSnapshot.mode,
      expectedRevision: runtimeSnapshot.revision,
      requestId,
    };
  }

  async function runRuntimeControl(action) {
    if (action !== "runtime-stop" && !supportedRuntimeActions.has(action)) return;
    const message = byId("runtime-message");
    message.className = "message";
    message.textContent = action === "runtime-stop" ? "Persisting STOP…" : "Persisting mode transition…";
    pendingRuntimeControls += 1;
    updateRuntimeButtons();
    try {
      const body = await requestJson("/api/control", {
        method: "POST",
        headers: { "content-type": "application/json", "x-rsi-operator-request": "1" },
        body: JSON.stringify(runtimeCommand(action)),
      });
      renderRuntime(body.result);
      message.textContent = action === "runtime-stop" ? "STOPPED is persisted." : "Runtime mode updated.";
      message.className = "message";
      void refresh();
    } catch (error) {
      message.textContent = error instanceof Error ? error.message : "Runtime control failed.";
      message.className = "message error";
    } finally {
      pendingRuntimeControls -= 1;
      updateRuntimeButtons();
    }
  }

  byId("refresh").addEventListener("click", refresh);
  for (const button of legacyButtons) {
    button.addEventListener("click", () => runLegacyControl(button.dataset.action));
  }
  for (const button of runtimeButtons) {
    button.addEventListener("click", () => runRuntimeControl(button.dataset.runtimeAction));
  }
  updateRuntimeButtons();
  void refresh();
})();
`;
