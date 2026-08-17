export const OPERATOR_DASHBOARD_HTML = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <meta name="color-scheme" content="dark">
    <title>RSI Observer</title>
    <link rel="stylesheet" href="/operator.css">
  </head>
  <body>
    <header class="masthead">
      <div>
        <p class="eyebrow">Recursive Self-Improvement</p>
        <h1>Observer console</h1>
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
          <h2 id="overview-title">Bounded observation, visible state</h2>
          <p class="lede">
            This console is confined to this computer. It can operate the supervised
            Observer lifecycle; it cannot edit policies, source plans, budgets,
            credentials, event history, or financial adapters.
          </p>
        </div>
        <button id="refresh" class="secondary" type="button">Refresh status</button>
      </section>

      <section class="grid" aria-label="Observer status">
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

        <article class="panel">
          <div class="panel-heading">
            <div>
              <p class="eyebrow">Supervised window</p>
              <h2>Session controls</h2>
            </div>
            <span id="control-state" class="badge neutral">Checking</span>
          </div>
          <p class="help">All actions are local, explicit, and recorded by the configured coordinator.</p>
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
              <p class="eyebrow">Human review</p>
              <h2>Feedback and candidate</h2>
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
      <span>RSI Observer v1</span>
      <span>Loopback only · no financial authority</span>
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
footer { display: flex; justify-content: space-between; gap: 1rem; max-width: 1180px; margin: 0 auto; border-top: 1px solid var(--line); padding: 1.3rem 1.4rem 2rem; color: var(--muted); font-size: .75rem; }

@media (max-width: 760px) {
  .masthead, .hero, footer { align-items: stretch; flex-direction: column; }
  .grid { grid-template-columns: 1fr; }
  .span-two { grid-column: auto; }
  .metric-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .event-list li { grid-template-columns: 1fr; gap: .3rem; }
}

@media (prefers-reduced-motion: reduce) { *, *::before, *::after { scroll-behavior: auto !important; } }
`;

export const OPERATOR_DASHBOARD_JS = `"use strict";
(() => {
  const byId = (id) => document.getElementById(id);
  const connection = byId("connection-status").parentElement;
  const controlButtons = Array.from(document.querySelectorAll("button[data-action]"));
  let supportedActions = new Set();

  const text = (value) => typeof value === "string" ? value : JSON.stringify(value);
  const safeSessionId = () => byId("session-id").value.trim();

  function setConnection(state, label) {
    connection.classList.remove("online", "offline");
    connection.classList.add(state);
    byId("connection-status").textContent = label;
  }

  function commandAction(buttonAction) {
    return buttonAction === "ack-45" || buttonAction === "ack-90" ? "acknowledge" : buttonAction;
  }

  function setControls(actions) {
    supportedActions = new Set(Array.isArray(actions) ? actions : []);
    for (const button of controlButtons) button.disabled = !supportedActions.has(commandAction(button.dataset.action));
    const enabled = supportedActions.size > 0;
    const badge = byId("control-state");
    badge.textContent = enabled ? "Available" : "Read only";
    badge.className = enabled ? "badge good" : "badge neutral";
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
    try {
      const [summary, events, capabilities] = await Promise.all([
        requestJson("/api/summary"),
        requestJson("/api/events?limit=12"),
        requestJson("/api/control/capabilities"),
      ]);
      renderSummary(summary.summary);
      renderEvents(events.events);
      setControls(capabilities.controls && capabilities.controls.enabled === true ? capabilities.controls.actions : []);
      setConnection("online", "Local connection ready");
    } catch (error) {
      setConnection("offline", "Local connection unavailable");
      byId("summary-state").textContent = "Unavailable";
      byId("summary-state").className = "badge bad";
      byId("control-message").textContent = error instanceof Error ? error.message : "Refresh failed.";
      byId("control-message").className = "message error";
    }
  }

  function commandFor(action) {
    const sessionId = safeSessionId();
    if (action === "plan") {
      const sessionId = crypto.randomUUID();
      byId("session-id").value = sessionId;
      return { action: "plan", sessionId };
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

  async function runControl(action) {
    if (!supportedActions.has(commandAction(action))) return;
    const message = byId("control-message");
    message.className = "message";
    message.textContent = "Working locally…";
    for (const button of controlButtons) button.disabled = true;
    try {
      const body = await requestJson("/api/control", {
        method: "POST",
        headers: { "content-type": "application/json", "x-rsi-operator-request": "1" },
        body: JSON.stringify(commandFor(action)),
      });
      const result = body.result || {};
      if (typeof result.sessionId === "string") byId("session-id").value = result.sessionId;
      message.textContent = "Local action completed.";
      await refresh();
    } catch (error) {
      message.textContent = error instanceof Error ? error.message : "Local action failed.";
      message.className = "message error";
    } finally {
      for (const button of controlButtons) button.disabled = !supportedActions.has(commandAction(button.dataset.action));
    }
  }

  byId("refresh").addEventListener("click", refresh);
  for (const button of controlButtons) {
    button.addEventListener("click", () => runControl(button.dataset.action));
  }
  refresh();
})();
`;
