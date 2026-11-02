// Browser-control checks with Node's built-in runner. No packages required.
const {test} = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const script = fs.readFileSync(path.join(__dirname, "../dashboard/static/dashboard/collected.js"), "utf8");
const settle = () => new Promise(resolve => setImmediate(resolve));

function page() {
    const timers = new Map();
    const pending = [];
    const calls = [];
    let nextTimer = 1;
    let selection = "";
    let focused = false;
    const status = {textContent: ""};
    const controls = {hidden: true};
    const toggle = {textContent: "", addEventListener(event, handler) {this[event] = handler;}, setAttribute() {}};
    const content = {
        dataset: {revision: "start"}, replacements: [],
        contains: () => focused,
        querySelectorAll: () => [],
        replaceChildren(...nodes) {this.replacements.push(nodes);},
    };
    const nodes = {"#collected-content": content, "[data-live-controls]": controls,
        "[data-live-status]": status, "[data-live-toggle]": toggle};
    const document = {
        hidden: false, activeElement: null,
        querySelector: selector => nodes[selector],
        addEventListener(event, handler) {this[event] = handler;},
    };
    const context = {
        document, URL, AbortController,
        window: {getSelection: () => ({toString: () => selection}), innerHeight: 800,
            scrollBy() {}, location: {origin: "http://localhost:8000", pathname: "/collected/1/"}},
        DOMParser: class {parseFromString(html) {return {body: {childNodes: [html]}};}},
        setTimeout(handler, delay) {const id = nextTimer++; timers.set(id, {handler, delay}); return id;},
        clearTimeout(id) {timers.delete(id);},
        fetch(url, options) {
            calls.push({url, options});
            return new Promise((resolve, reject) => pending.push({resolve, reject}));
        },
    };
    vm.runInNewContext(script, context);
    return {content, controls, status, toggle, document, calls, pending,
        select(value) {selection = value;}, focus(value) {focused = value;},
        async response(data = {revision: "next", html: "escaped fragment", states: []}) {
            pending.shift().resolve({ok: true, json: async () => data}); await settle();
        },
        async tick() {
            const entry = [...timers].find(([, timer]) => timer.delay === 2000);
            assert.ok(entry, "next update must be scheduled");
            timers.delete(entry[0]); entry[1].handler(); await settle();
        },
        timerCount() {return timers.size;},
    };
}

test("new data refreshes the fragment; unchanged data preserves it", async () => {
    const app = page();
    assert.equal(app.controls.hidden, false);
    assert.equal(app.calls[0].options.headers["X-LogSentry-Update"], "1");
    assert.equal(app.calls[0].options.cache, "no-store");
    await app.response();
    assert.equal(app.content.replacements.length, 1);
    await app.tick();
    assert.equal(app.calls[1].url.searchParams.get("revision"), "next");
    await app.response({revision: "next", html: null, states: []});
    assert.equal(app.content.replacements.length, 1);
    assert.match(app.status.textContent, /checking every 2 seconds/);
});

test("failed requests preserve records and retry successfully", async () => {
    const app = page();
    app.pending.shift().reject(new Error("offline"));
    await settle();
    assert.match(app.status.textContent, /Connection interrupted/);
    assert.equal(app.content.replacements.length, 0);
    await app.tick();
    await app.response();
    assert.equal(app.content.replacements.length, 1);
});

test("pause discards an in-flight response and resume requests again", async () => {
    const app = page();
    app.toggle.click();
    assert.equal(app.calls[0].options.signal.aborted, true);
    await app.response();
    assert.equal(app.content.replacements.length, 0);
    assert.equal(app.timerCount(), 0);
    assert.match(app.status.textContent, /Updates paused/);
    app.toggle.click();
    await app.response();
    assert.equal(app.content.replacements.length, 1);
});

test("hidden tabs suspend requests and refresh when visible", async () => {
    const app = page();
    app.document.hidden = true;
    app.document.visibilitychange();
    await app.response();
    assert.equal(app.content.replacements.length, 0);
    assert.equal(app.timerCount(), 0);
    app.document.hidden = false;
    app.document.visibilitychange();
    await app.response();
    assert.equal(app.content.replacements.length, 1);
});

test("text selection and focused links defer updates without losing the revision", async () => {
    const app = page();
    app.select("reading this record");
    await app.response();
    assert.equal(app.content.replacements.length, 0);
    await app.tick();
    assert.equal(app.calls.length, 1);
    app.select("");
    app.focus(true);
    await app.tick();
    assert.equal(app.calls.length, 1);
    app.focus(false);
    await app.tick();
    assert.equal(app.calls[1].url.searchParams.get("revision"), "start");
    await app.response();
    assert.equal(app.content.replacements.length, 1);
});

test("collector attention is distinct from a working page connection", async () => {
    const app = page();
    await app.response({revision: "next", html: null, states: [{id: 1, attention: true}]});
    assert.match(app.status.textContent, /check collection state/);
    assert.doesNotMatch(app.status.textContent, /Connection interrupted/);
});

test("invalid responses preserve records and schedule a retry", async () => {
    const app = page();
    await app.response({revision: "bad", html: 42, states: []});
    assert.equal(app.content.replacements.length, 0);
    assert.match(app.status.textContent, /Connection interrupted/);
    await app.tick();
    assert.equal(app.calls.length, 2);
});
