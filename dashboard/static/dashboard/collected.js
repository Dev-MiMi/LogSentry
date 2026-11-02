/* Keep the collected page current without reloading the whole document.
 * The collector and browser have separate clocks: this checks saved results
 * every two seconds, and explicitly shows failures instead of pretending live.
 */
(() => {
    "use strict";
    const content = document.querySelector("#collected-content");
    if (!content) return;
    const controls = document.querySelector("[data-live-controls]");
    const status = document.querySelector("[data-live-status]");
    const toggle = document.querySelector("[data-live-toggle]");
    const interval = 2000;
    let revision = content.dataset.revision;
    let paused = false;
    let timer;
    let controller;
    let generation = 0;
    controls.hidden = false;

    function schedule() {
        clearTimeout(timer);
        if (!paused && !document.hidden) timer = setTimeout(update, interval);
    }

    function reading() {
        // Do not erase a selection or a link being used with the keyboard.
        return Boolean(window.getSelection()?.toString()) || content.contains(document.activeElement);
    }

    function replaceRecords(html) {
        // Markup comes from our escaped Django template, never raw log strings.
        const parsed = new DOMParser().parseFromString(html, "text/html");
        const anchor = [...content.querySelectorAll("[data-record-id]")].find(element => {
            const box = element.getBoundingClientRect();
            return box.bottom > 0 && box.top < window.innerHeight;
        });
        const oldTop = anchor?.getBoundingClientRect().top;
        const recordId = anchor?.dataset.recordId;
        content.replaceChildren(...parsed.body.childNodes);
        // Keep a record in view when newer records are inserted above it.
        const replacement = recordId && [...content.querySelectorAll("[data-record-id]")]
            .find(element => element.dataset.recordId === recordId);
        if (replacement) window.scrollBy(0, replacement.getBoundingClientRect().top - oldTop);
    }

    function showStates(states) {
        for (const row of content.querySelectorAll("[data-source-id]")) {
            const state = states.find(item => String(item.id) === row.dataset.sourceId);
            if (!state) continue;
            row.querySelector("[data-last-check]").textContent = state.last_checked;
            const label = row.querySelector("[data-collection-state]");
            label.textContent = state.label;
            label.classList.toggle("text-orange", state.attention);
        }
    }

    async function update() {
        clearTimeout(timer);
        if (paused || document.hidden || controller) return;
        if (reading()) {
            status.textContent = "Reading records · updates waiting";
            schedule();
            return;
        }
        const currentGeneration = generation;
        const active = new AbortController();
        controller = active;
        const timeout = setTimeout(() => active.abort(), 10000);
        try {
            const url = new URL(window.location.pathname, window.location.origin);
            url.searchParams.set("revision", revision);
            const response = await fetch(url, {
                headers: {"X-LogSentry-Update": "1"},
                cache: "no-store", credentials: "same-origin", signal: active.signal,
            });
            if (!response.ok) throw new Error("Update unavailable");
            const data = await response.json();
            if (typeof data.revision !== "string" || !Array.isArray(data.states) ||
                (data.html !== null && typeof data.html !== "string")) throw new Error("Invalid update");
            // Pausing/hiding while a request is in flight must discard its result.
            if (currentGeneration !== generation || paused || document.hidden) return;
            if (reading()) {
                status.textContent = "Reading records · updates waiting";
                return;
            }
            if (data.html !== null) replaceRecords(data.html);
            revision = data.revision;
            showStates(data.states);
            status.textContent = data.states.some(item => item.attention)
                ? "Page updates on · check collection state below"
                : "Page updates on · checking every 2 seconds";
        } catch (error) {
            if (currentGeneration === generation && !paused && !document.hidden) {
                status.textContent = "Connection interrupted · showing saved results and retrying";
            }
        } finally {
            clearTimeout(timeout);
            if (controller === active) controller = null;
            if (currentGeneration === generation) schedule();
        }
    }

    function cancelPending() {
        generation += 1;
        clearTimeout(timer);
        controller?.abort();
        controller = null;
    }

    toggle.addEventListener("click", () => {
        paused = !paused;
        cancelPending();
        toggle.textContent = paused ? "Resume updates" : "Pause updates";
        toggle.setAttribute("aria-pressed", String(paused));
        status.textContent = paused ? "Updates paused · collector continues saving records" : "Connecting to updates…";
        if (!paused) update();
    });
    document.addEventListener("visibilitychange", () => {
        cancelPending();
        if (document.hidden) status.textContent = "Page updates paused while this tab is hidden";
        else if (!paused) update();
        else status.textContent = "Updates paused · collector continues saving records";
    });
    update();
})();
