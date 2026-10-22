export const ATTENTION_DASHBOARD_HTML = `<article id="attention-panel" class="panel span-two attention-panel" aria-busy="false">
  <div class="panel-heading">
    <div>
      <p class="eyebrow">Recorded Base collection attention</p>
      <h2>Research attention queue</h2>
    </div>
    <span id="attention-status" class="badge neutral" aria-live="polite">Checking</span>
  </div>
  <p class="attention-warning">
    Provenance is always operator_supplied_unverified. Rank and recorded social activity
    do not prove legitimacy, expected return, or that you should buy anything. This flow
    reads one local file and makes no provider, wallet, payment, or transaction request.
  </p>
  <p class="help">
    For a fictional local walkthrough, run
    <code>mkdir -p .local/stage0 &amp;&amp; pnpm --silent demo:attention-fixture &gt; .local/stage0/recorded-attention-demo.json</code>.
    The modeled rank window spans 120 seconds and has about 90 seconds remaining when generated.
    Create it immediately before Preview. The browser reads the raw JSON on Preview and retains its
    parsed value in memory only for the current preview-to-record draft; it never renders the raw
    file. Operator responses never echo the original JSON, and durable history never persists raw X
    text, post IDs, or original JSON. This is recorded test material, not live monitoring.
  </p>
  <label>
    Recorded attention JSON file
    <input id="attention-file" type="file" accept="application/json,.json">
  </label>
  <div class="runtime-actions attention-actions">
    <button id="attention-preview" type="button" disabled>Preview recorded evidence</button>
    <button id="attention-record" type="button" disabled>Record exact preview</button>
  </div>
  <p id="attention-message" class="message" aria-live="polite">
    Enter RESEARCH and choose a local JSON file. Nothing is sent until you select Preview.
  </p>

  <section id="attention-preview-section" class="attention-section" aria-labelledby="attention-preview-title" hidden>
    <h3 id="attention-preview-title">Unrecorded preview</h3>
    <p id="attention-preview-meta" class="help">No preview.</p>
    <dl id="attention-preview-source" class="attention-facts"></dl>
    <ol id="attention-preview-diagnostics" class="attention-list"></ol>
    <ol id="attention-preview-rows" class="proposal-list"></ol>
  </section>

  <section class="attention-section" aria-labelledby="attention-current-title">
    <h3 id="attention-current-title">Durable queue</h3>
    <p id="attention-state" class="help">No recorded attention batch.</p>
    <p id="attention-audit" class="proposal-detail">No audit head.</p>
    <dl id="attention-source" class="attention-facts"></dl>
    <ol id="attention-diagnostics" class="attention-list"></ol>
    <ol id="attention-rows" class="proposal-list"></ol>
  </section>

  <details>
    <summary>Recorded batch history</summary>
    <ol id="attention-history" class="attention-list"><li>No recorded batches.</li></ol>
  </details>
</article>`;

export const ATTENTION_DASHBOARD_CSS = `.attention-panel { border-color: #4a4627; }
.attention-actions { grid-template-columns: repeat(2, minmax(0, 1fr)); margin-top: .8rem; }
.attention-warning { border: 1px solid #665729; border-radius: 12px; background: #211c0d; padding: .85rem; color: var(--warning); font-size: .82rem; line-height: 1.5; }
.attention-section { border-top: 1px solid var(--line); margin-top: 1rem; padding-top: 1rem; }
.attention-section h3 { margin: 0 0 .55rem; font-size: .95rem; }
.attention-facts { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: .55rem; margin: .7rem 0; }
.attention-facts .metric { padding: .65rem; }
.attention-list { display: grid; gap: .45rem; margin: .65rem 0; padding-left: 1.25rem; color: var(--muted); font: .76rem/1.55 ui-monospace, SFMono-Regular, Menlo, monospace; }
.attention-list li { overflow-wrap: anywhere; }
.attention-outcomes { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: .55rem; }
.attention-outcomes .proposal-detail { border: 1px solid var(--line); border-radius: 10px; padding: .65rem; }

@media (max-width: 760px) {
  .attention-facts, .attention-outcomes { grid-template-columns: 1fr; }
}`;

export const ATTENTION_DASHBOARD_JS = `"use strict";
(() => {
  const byId = (id) => document.getElementById(id);
  let runtimeSnapshot = null;
  let attentionAvailable = false;
  let attentionDraft = { kind: "idle" };
  let attentionGeneration = 0;
  let attentionReadGeneration = 0;
  let attentionHeadIdentity;
  let attentionDeadlineTimer = null;
  let attentionLastClock = Date.now();

  function attentionHeadKey(head) {
    return head === null
      ? "empty"
      : String(head.sequence) + ":" + head.refreshId + ":" + head.eventHash;
  }

  function attentionBindingHeadKey(binding) {
    return attentionHeadKey(binding.auditHead);
  }

  function attentionFile() {
    const files = byId("attention-file").files;
    return files && files[0] ? files[0] : null;
  }

  function setAttentionMessage(message, isError) {
    const element = byId("attention-message");
    element.textContent = message;
    element.className = isError ? "message error" : "message";
  }

  function clearAttentionDeadline() {
    if (attentionDeadlineTimer !== null) clearTimeout(attentionDeadlineTimer);
    attentionDeadlineTimer = null;
  }

  function discardAttentionPreview(message, isError) {
    attentionGeneration += 1;
    clearAttentionDeadline();
    attentionDraft = { kind: "idle" };
    byId("attention-preview-section").hidden = true;
    byId("attention-preview-meta").textContent = "No preview.";
    byId("attention-preview-source").replaceChildren();
    byId("attention-preview-diagnostics").replaceChildren();
    byId("attention-preview-rows").replaceChildren();
    if (message) setAttentionMessage(message, isError === true);
  }

  function resetAttentionPreview(message, isError) {
    discardAttentionPreview(message, isError);
    updateAttentionButtons();
  }

  function attentionRuntimeMatches(binding) {
    return runtimeSnapshot !== null &&
      binding.processInstanceId === runtimeSnapshot.processInstanceId &&
      binding.modeRevision === runtimeSnapshot.revision &&
      runtimeSnapshot.mode === "RESEARCH";
  }

  function attentionReadyIsCurrent() {
    if (attentionDraft.kind !== "ready") return false;
    const now = Date.now();
    if (now < attentionLastClock) {
      discardAttentionPreview("The local clock moved backwards. Refresh before previewing again.", true);
      return false;
    }
    attentionLastClock = now;
    if (now >= Date.parse(attentionDraft.binding.deadline)) {
      discardAttentionPreview("The preview expired. Preview the file again. The server clock remains authoritative.", true);
      return false;
    }
    if (!attentionRuntimeMatches(attentionDraft.binding) ||
      attentionBindingHeadKey(attentionDraft.binding) !== attentionHeadIdentity) {
      discardAttentionPreview("The preview context changed. Preview the file again.", true);
      return false;
    }
    return true;
  }

  function updateAttentionButtons() {
    const busy = attentionDraft.kind === "previewing" || attentionDraft.kind === "recording";
    byId("attention-panel").setAttribute("aria-busy", busy ? "true" : "false");
    byId("attention-preview").disabled = busy || !attentionAvailable ||
      runtimeSnapshot === null || runtimeSnapshot.mode !== "RESEARCH" ||
      attentionFile() === null;
    byId("attention-record").disabled = busy || !attentionReadyIsCurrent();
  }

  function expireAttentionPreview(generation, previewId) {
    if (attentionDraft.kind !== "ready" ||
      attentionDraft.generation !== generation ||
      attentionDraft.binding.previewId !== previewId) return;
    resetAttentionPreview("The preview expired. Preview the file again. The server clock remains authoritative.", true);
  }

  function armAttentionDeadline() {
    clearAttentionDeadline();
    if (attentionDraft.kind !== "ready") return;
    const delay = Math.min(30000, Math.max(0, Date.parse(attentionDraft.binding.deadline) - Date.now()));
    const generation = attentionDraft.generation;
    const previewId = attentionDraft.binding.previewId;
    attentionDeadlineTimer = setTimeout(
      () => expireAttentionPreview(generation, previewId),
      delay,
    );
  }

  function appendMetric(root, label, value) {
    const wrapper = document.createElement("div");
    wrapper.className = "metric";
    const term = document.createElement("dt");
    term.textContent = label;
    const definition = document.createElement("dd");
    definition.textContent = String(value);
    wrapper.append(term, definition);
    root.append(wrapper);
  }

  function appendDetail(card, label, value) {
    const detail = document.createElement("div");
    detail.className = "proposal-detail";
    detail.textContent = label + ": " + value;
    card.append(detail);
  }

  function outcomeText(outcome) {
    const priority = outcome.priority === null ? "none" : String(outcome.priority) + "/60 attention";
    const reasons = Array.isArray(outcome.reasons) && outcome.reasons.length > 0
      ? " · reasons " + outcome.reasons.join(", ")
      : "";
    return outcome.kind + " · priority " + priority + reasons;
  }

  function presenceText(presence) {
    return presence.kind === "observed"
      ? "observed · rank " + String(presence.rank)
      : "left window · prior rank " + String(presence.previousRank);
  }

  function comparisonText(comparison) {
    if (comparison.kind === "comparable") {
      return "comparable · prior rank " + String(comparison.previousRank) +
        " · rank delta " + String(comparison.delta) + " (positive means upward)";
    }
    return comparison.kind === "not_comparable"
      ? "not comparable · " + comparison.reason
      : "not observed";
  }

  function timeValidity(valid) {
    return valid
      ? "time-valid for this local assessment (unverified)"
      : "outside the local assessment time window (unverified)";
  }

  function renderSource(root, sourceSummary) {
    root.replaceChildren();
    const marketplace = sourceSummary.marketplace;
    appendMetric(root, "Rank timing", timeValidity(marketplace.usable));
    appendMetric(root, "Rank candidates", marketplace.candidateCount);
    appendMetric(root, "Rank acquired", marketplace.acquiredAt);
    appendMetric(root, "Rank valid until", marketplace.validUntil);
    appendMetric(root, "Rank next page", marketplace.hasNextPage ? "reported" : "none");
    appendMetric(root, "Prior rank evidence", marketplace.priorUsableWindowId || "none");

    const social = sourceSummary.x;
    appendMetric(root, "Recorded X", social.kind);
    if (social.kind === "observed") {
      appendMetric(root, "X posts", social.postCount);
      appendMetric(root, "Bound clusters", social.usableBoundClusterCount);
      appendMetric(root, "X acquired", social.acquiredAt);
      appendMetric(root, "X valid until", social.validUntil);
      appendMetric(root, "X next page", social.hasNextPage ? "reported" : "none");
    }

    const base = sourceSummary.base;
    appendMetric(root, "Base context", base.kind === "usable"
      ? "time-valid for this local assessment (unverified)"
      : base.kind);
    if (base.kind === "usable" || base.kind === "stale") {
      appendMetric(root, "Base acquired", base.acquiredAt);
      appendMetric(root, "Base valid until", base.validUntil);
      appendMetric(root, "Base block time", base.blockTimestamp);
    }
  }

  function renderDiagnostics(root, diagnostics) {
    root.replaceChildren();
    if (diagnostics.length === 0) {
      const item = document.createElement("li");
      item.textContent = "No source diagnostics.";
      root.append(item);
      return;
    }
    for (const diagnostic of diagnostics) {
      const item = document.createElement("li");
      item.textContent = diagnostic.code + " · evidence " + diagnostic.evidenceId;
      root.append(item);
    }
  }

  function renderRows(root, rows, effective) {
    root.replaceChildren();
    if (rows.length === 0) {
      const empty = document.createElement("li");
      empty.textContent = "No collection rows in this batch.";
      root.append(empty);
      return;
    }
    for (const item of rows) {
      const saved = effective ? item.saved : item;
      const card = document.createElement("li");
      card.className = "proposal-card";
      const title = document.createElement("div");
      title.className = "proposal-title";
      const label = document.createElement("strong");
      label.textContent = saved.slug;
      const badge = document.createElement("span");
      const effectiveOutcome = effective ? item.effectiveOutcome : saved.outcome;
      badge.className = effectiveOutcome.kind === "rejected" ? "badge bad" : "badge neutral";
      badge.textContent = effectiveOutcome.kind;
      title.append(label, badge);
      card.append(title);

      if (saved.subject.kind === "resolved") {
        appendDetail(card, "Base identity", "chain " + saved.subject.identity.chainId +
          " · contracts " + saved.subject.identity.contracts.join(", "));
        appendDetail(card, "Collection ID", saved.subject.identity.collectionId);
      } else {
        appendDetail(card, "Unresolved candidate ID", saved.subject.candidateId);
      }
      appendDetail(card, "Presence", presenceText(saved.presence));
      appendDetail(card, "Rank comparison", comparisonText(saved.comparison));
      appendDetail(card, "Evidence IDs", saved.evidenceIds.length > 0 ? saved.evidenceIds.join(", ") : "none");
      appendDetail(card, "Assessed", saved.assessedAt);
      appendDetail(card, "Expires", saved.expiresAt);
      appendDetail(card, "Provenance", saved.provenance.kind + " · " +
        saved.provenance.streamId + " · bundle " + saved.provenance.bundleId);
      appendDetail(card, "Missing checks", saved.missingChecks.length > 0 ? saved.missingChecks.join(", ") : "none");
      appendDetail(card, "Notes", saved.notes.length > 0 ? saved.notes.join(", ") : "none");

      const outcomes = document.createElement("div");
      outcomes.className = "attention-outcomes";
      const savedOutcome = document.createElement("div");
      savedOutcome.className = "proposal-detail";
      savedOutcome.textContent = "Saved outcome: " + outcomeText(saved.outcome) +
        " · next action " + saved.nextAction;
      outcomes.append(savedOutcome);
      if (effective) {
        const currentOutcome = document.createElement("div");
        currentOutcome.className = "proposal-detail";
        currentOutcome.textContent = "Effective now: " + outcomeText(item.effectiveOutcome) +
          " · next action " + item.effectiveNextAction +
          (item.expired ? " · expired overlay" : " · unchanged");
        outcomes.append(currentOutcome);
      }
      card.append(outcomes);

      if (saved.scorecard !== null) {
        const scores = document.createElement("dl");
        scores.className = "score-grid";
        appendMetric(scores, "Rank attention /40", saved.scorecard.rank);
        appendMetric(scores, "Upward movement /10", saved.scorecard.upwardMovement);
        appendMetric(scores, "Recorded social /10", saved.scorecard.socialPresence);
        appendMetric(scores, "Attention total /60", saved.scorecard.total);
        appendMetric(scores, "Observed clusters", saved.scorecard.observedContentClusters);
        appendMetric(scores, "Counted clusters", saved.scorecard.countedContentClusters);
        card.append(scores);
      }
      root.append(card);
    }
  }

  function renderAssessment(assessment) {
    renderSource(byId("attention-preview-source"), assessment.sourceSummary);
    renderDiagnostics(byId("attention-preview-diagnostics"), assessment.diagnostics);
    renderRows(byId("attention-preview-rows"), assessment.rows, false);
  }

  function renderHistory(history) {
    const root = byId("attention-history");
    root.replaceChildren();
    if (history.length === 0) {
      const empty = document.createElement("li");
      empty.textContent = "No recorded batches.";
      root.append(empty);
      return;
    }
    for (const entry of history) {
      const item = document.createElement("li");
      item.textContent = "sequence " + String(entry.head.sequence) +
        " · refresh " + entry.head.refreshId +
        " · event " + entry.head.eventHash +
        " · bundle " + entry.bundleId +
        " · predecessor " + (entry.predecessorId || "none") +
        " · acquired " + entry.acquiredAt +
        " · valid until " + entry.validUntil +
        " · evaluated " + entry.evaluatedAt +
        " · recorded " + entry.checkpointAt +
        " · rank timing " + timeValidity(entry.usableRankWindow);
      root.append(item);
    }
  }

  function renderView(view) {
    if (view.kind === "unavailable") {
      attentionAvailable = false;
      attentionHeadIdentity = undefined;
      resetAttentionPreview("The attention view is unavailable because the read clock moved backwards.", true);
      const status = byId("attention-status");
      status.textContent = "Clock regressed";
      status.className = "badge bad";
      byId("attention-state").textContent = "Current time " + view.evaluatedAt +
        " is earlier than the latest checkpoint " + view.latestCheckpointAt + ".";
      byId("attention-audit").textContent = "No trusted current audit head.";
      byId("attention-source").replaceChildren();
      byId("attention-diagnostics").replaceChildren();
      byId("attention-rows").replaceChildren();
      renderHistory([]);
      updateAttentionButtons();
      return;
    }

    attentionAvailable = true;
    const nextHeadIdentity = attentionHeadKey(view.auditHead);
    if (attentionHeadIdentity !== undefined &&
      attentionHeadIdentity !== nextHeadIdentity &&
      attentionDraft.kind !== "idle") {
      resetAttentionPreview("The recorded attention head changed. Preview the file again.", true);
    }
    attentionHeadIdentity = nextHeadIdentity;
    const status = byId("attention-status");
    status.textContent = view.latest === null ? "Ready" : "Recorded";
    status.className = "badge neutral";
    byId("attention-state").textContent = "Provenance " + view.provenance +
      " · evaluated " + view.evaluatedAt +
      (view.latest === null ? " · no batch recorded" : " · latest bundle " + view.latest.assessment.bundleId);
    byId("attention-audit").textContent = view.auditHead === null
      ? "No audit head."
      : "Audit head: sequence " + String(view.auditHead.sequence) +
        " · refresh " + view.auditHead.refreshId + " · event " + view.auditHead.eventHash;
    if (view.latest === null) {
      byId("attention-source").replaceChildren();
      byId("attention-diagnostics").replaceChildren();
      renderRows(byId("attention-rows"), [], true);
    } else {
      renderSource(byId("attention-source"), view.latest.assessment.sourceSummary);
      renderDiagnostics(byId("attention-diagnostics"), view.latest.assessment.diagnostics);
      renderRows(byId("attention-rows"), view.rows, true);
    }
    renderHistory(view.history);
    updateAttentionButtons();
  }

  function clearView(message) {
    attentionAvailable = false;
    attentionHeadIdentity = undefined;
    resetAttentionPreview(message, true);
    const status = byId("attention-status");
    status.textContent = "Unavailable";
    status.className = "badge neutral";
    byId("attention-state").textContent = "Recorded collection attention is unavailable.";
    byId("attention-audit").textContent = "No audit head.";
    byId("attention-source").replaceChildren();
    byId("attention-diagnostics").replaceChildren();
    byId("attention-rows").replaceChildren();
    renderHistory([]);
    updateAttentionButtons();
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

  async function refreshContext() {
    const generation = ++attentionReadGeneration;
    const [runtime, attention] = await Promise.allSettled([
      requestJson("/api/runtime"),
      requestJson("/api/attention"),
    ]);
    if (generation !== attentionReadGeneration) return;
    if (runtime.status === "fulfilled") {
      const next = runtime.value.runtime;
      if (runtimeSnapshot !== null &&
        (runtimeSnapshot.mode !== next.mode ||
          runtimeSnapshot.revision !== next.revision ||
          runtimeSnapshot.processInstanceId !== next.processInstanceId)) {
        resetAttentionPreview("The runtime state changed. Preview the recorded evidence again.", true);
      }
      runtimeSnapshot = next;
    } else {
      runtimeSnapshot = null;
      resetAttentionPreview("Runtime status is unavailable. Preview is disabled.", true);
    }
    if (attention.status === "fulfilled") renderView(attention.value.attention);
    else clearView("Recorded collection attention could not be read.");
    updateAttentionButtons();
  }

  async function readView() {
    const generation = ++attentionReadGeneration;
    try {
      const body = await requestJson("/api/attention");
      if (generation === attentionReadGeneration) renderView(body.attention);
    } catch {
      if (generation === attentionReadGeneration) {
        clearView("Recorded collection attention could not be read.");
      }
    }
  }

  async function previewAttention() {
    if (byId("attention-preview").disabled) return;
    const file = attentionFile();
    if (file === null || file.size > 60000) {
      resetAttentionPreview("Choose a valid recorded JSON file no larger than 60,000 bytes.", true);
      return;
    }
    resetAttentionPreview();
    const generation = attentionGeneration;
    const startedAt = Date.now();
    attentionLastClock = startedAt;
    attentionDraft = { kind: "previewing", generation };
    setAttentionMessage("Reading the selected local file for preview.", false);
    updateAttentionButtons();

    let input;
    try {
      input = JSON.parse(await file.text());
    } catch {
      if (generation === attentionGeneration) {
        resetAttentionPreview("Choose a valid recorded attention JSON file.", true);
      }
      return;
    }
    if (generation !== attentionGeneration || file !== attentionFile()) return;

    try {
      const body = await requestJson("/api/attention/preview", {
        method: "POST",
        headers: { "content-type": "application/json", "x-rsi-operator-request": "1" },
        body: JSON.stringify({ input }),
      });
      if (generation !== attentionGeneration || file !== attentionFile()) return;
      const now = Date.now();
      if (now < startedAt) {
        resetAttentionPreview("The local clock moved backwards. Refresh before previewing again.", true);
        return;
      }
      attentionLastClock = now;
      if (body.preview.kind === "already_recorded") {
        resetAttentionPreview("This exact evidence batch is already recorded. No new authorization was created.", false);
        await readView();
        return;
      }
      const preview = body.preview;
      if (!attentionRuntimeMatches(preview.binding) ||
        attentionBindingHeadKey(preview.binding) !== attentionHeadIdentity ||
        now >= Date.parse(preview.binding.deadline)) {
        resetAttentionPreview("The preview context changed or expired. Refresh and preview the file again.", true);
        return;
      }
      attentionDraft = {
        kind: "ready",
        generation,
        input,
        binding: preview.binding,
      };
      byId("attention-preview-section").hidden = false;
      byId("attention-preview-meta").textContent = "Bundle " + preview.binding.bundleId +
        " · refresh " + preview.binding.refreshId +
        " · policy " + preview.binding.policyVersion +
        " · evaluated " + preview.binding.evaluatedAt +
        " · expires " + preview.binding.deadline;
      renderAssessment(preview.assessment);
      setAttentionMessage("Review the preview. Record sends only this exact server binding and the selected input.", false);
      armAttentionDeadline();
      updateAttentionButtons();
    } catch (error) {
      if (generation === attentionGeneration) {
        resetAttentionPreview(error instanceof Error ? error.message : "Preview failed.", true);
      }
    }
  }

  async function recordAttention() {
    if (byId("attention-record").disabled || attentionDraft.kind !== "ready") return;
    if (!attentionReadyIsCurrent() || attentionDraft.kind !== "ready") {
      updateAttentionButtons();
      return;
    }
    const command = { input: attentionDraft.input, expected: attentionDraft.binding };
    attentionGeneration += 1;
    const generation = attentionGeneration;
    clearAttentionDeadline();
    attentionDraft = { kind: "recording", generation };
    byId("attention-preview-section").hidden = true;
    setAttentionMessage("Recording the exact preview locally.", false);
    updateAttentionButtons();
    try {
      await requestJson("/api/attention/record", {
        method: "POST",
        headers: { "content-type": "application/json", "x-rsi-operator-request": "1" },
        body: JSON.stringify(command),
      });
      if (attentionDraft.kind === "recording" && attentionDraft.generation === generation) {
        attentionDraft = { kind: "idle" };
        setAttentionMessage("The exact preview is recorded in the local attention history.", false);
        updateAttentionButtons();
      }
      await readView();
    } catch (error) {
      if (attentionDraft.kind === "recording" && attentionDraft.generation === generation) {
        attentionDraft = { kind: "idle" };
        setAttentionMessage(
          (error instanceof Error ? error.message : "Recording failed.") + " Preview the file again before retrying.",
          true,
        );
        updateAttentionButtons();
      }
    }
  }

  byId("attention-file").addEventListener("change", () => {
    resetAttentionPreview("File selected. Preview reads it locally and sends it only when requested.", false);
  });
  byId("attention-preview").addEventListener("click", previewAttention);
  byId("attention-record").addEventListener("click", recordAttention);
  byId("refresh").addEventListener("click", refreshContext);
  if (typeof document.addEventListener === "function") {
    document.addEventListener("rsi:runtime-changing", () => {
      runtimeSnapshot = null;
      resetAttentionPreview("The runtime is changing. Preview the recorded evidence again afterward.", false);
    });
    document.addEventListener("rsi:runtime-changed", refreshContext);
  }
  updateAttentionButtons();
  void refreshContext();
})();
`;

export const ATTENTION_DASHBOARD_ASSETS = Object.freeze({
  css: ATTENTION_DASHBOARD_CSS,
  html: ATTENTION_DASHBOARD_HTML,
  js: ATTENTION_DASHBOARD_JS,
  runtimeBridge: `function signalRuntimeChange(type) {
    if (typeof Event === "function" && typeof document.dispatchEvent === "function") {
      document.dispatchEvent(new Event(type));
    }
  }`,
});
