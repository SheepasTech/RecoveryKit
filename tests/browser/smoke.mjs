// Browser smoke test for the control-server page: drives real Edge through the Chrome DevTools Protocol.
// No npm packages. Needs Node 22+ (global WebSocket and fetch) and Microsoft Edge. Everything is 127.0.0.1.
import { spawn } from "node:child_process";
import { createServer } from "node:net";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..", "..");
const OUT = join(HERE, "out");
const EDGES = ["C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
  "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe"];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const results = [];
const findings = { console: [], exceptions: [], netfail: [], external: [], csp: [] };
const reqLog = [], dialogs = [];
let curStep = "setup";
let fixture = null, edge = null, edgeDir = null, ws = null;
let nextId = 1;
const pending = new Map();
const listeners = [];

function freePort() {
  return new Promise((res, rej) => {
    const s = createServer();
    s.listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => res(p)); });
    s.on("error", rej);
  });
}
function send(method, params = {}) {
  return new Promise((res, rej) => {
    const id = nextId++;
    pending.set(id, { res, rej, method });
    ws.send(JSON.stringify({ id, method, params }));
  });
}
function on(method, fn) { listeners.push([method, fn]); }
async function ev(expr) {
  const r = await send("Runtime.evaluate", { expression: expr, returnByValue: true, awaitPromise: true });
  if (r.exceptionDetails) throw new Error("evaluate failed: " + (r.exceptionDetails.exception?.description || r.exceptionDetails.text));
  return r.result.value;
}
async function waitFor(expr, ms, what) {
  const end = Date.now() + ms;
  for (;;) {
    let v = false;
    try { v = await ev(expr); } catch { v = false; }
    if (v) return v;
    if (Date.now() > end) throw new Error("timed out after " + ms + " ms waiting for " + (what || expr));
    await sleep(150);
  }
}
const q = JSON.stringify;
const body = () => ev("document.body.innerText");
function check(cond, msg) { if (!cond) throw new Error(msg); }

async function step(name, fn) {
  curStep = name;
  try { await fn(); results.push([name, true, ""]); }
  catch (e) { results.push([name, false, e.message]); }
}

async function shot(name) {
  mkdirSync(OUT, { recursive: true });
  let wide = 0;
  for (const [w, suffix] of [[1280, ""], [420, "-420"]]) {
    await send("Emulation.setDeviceMetricsOverride", { width: w, height: 900, deviceScaleFactor: 1, mobile: false });
    await sleep(250);
    const r = await send("Page.captureScreenshot", { format: "png" });
    writeFileSync(join(OUT, name + suffix + ".png"), Buffer.from(r.data, "base64"));
    if (w === 420) wide = await ev("document.documentElement.scrollWidth");
  }
  await send("Emulation.setDeviceMetricsOverride", { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });
  if (wide > 421) throw new Error("page scrolls horizontally at 420 px (scrollWidth " + wide + ") in " + name);
}

async function setupFixture() {
  fixture = spawn("python", [join(HERE, "serve_fixture.py")], { cwd: ROOT, stdio: ["pipe", "pipe", "pipe"] });
  let err = "";
  fixture.stderr.on("data", (d) => { err += d; });
  const line = await new Promise((res, rej) => {
    let buf = "";
    fixture.stdout.on("data", (d) => { buf += d; const i = buf.indexOf("\n"); if (i >= 0) res(buf.slice(0, i)); });
    fixture.on("exit", () => rej(new Error("fixture exited early: " + err.slice(-500))));
    setTimeout(() => rej(new Error("fixture did not start in 60 s: " + err.slice(-500))), 60000);
  });
  return JSON.parse(line);
}

async function setupBrowser() {
  const exe = EDGES.find(existsSync);
  if (!exe) throw new Error("msedge.exe not found");
  const port = await freePort();
  edgeDir = mkdtempSync(join(tmpdir(), "rk-edge-"));
  edge = spawn(exe, ["--headless=new", "--remote-debugging-port=" + port, "--user-data-dir=" + edgeDir,
    "--no-first-run", "--disable-extensions", "about:blank"], { stdio: "ignore" });
  let targets = null;
  for (let i = 0; i < 100 && !targets; i++) {
    try {
      const r = await fetch("http://127.0.0.1:" + port + "/json");
      const t = (await r.json()).filter((x) => x.type === "page");
      if (t.length) targets = t;
    } catch { /* not up yet */ }
    if (!targets) await sleep(200);
  }
  if (!targets) throw new Error("Edge did not expose a page target");
  ws = new WebSocket(targets[0].webSocketDebuggerUrl);
  await new Promise((res, rej) => { ws.onopen = res; ws.onerror = () => rej(new Error("CDP websocket failed")); });
  ws.onmessage = (m) => {
    const d = JSON.parse(m.data);
    if (d.id && pending.has(d.id)) {
      const p = pending.get(d.id); pending.delete(d.id);
      if (d.error) p.rej(new Error(p.method + ": " + d.error.message)); else p.res(d.result);
    } else if (d.method) {
      for (const [mm, fn] of listeners) if (mm === d.method) fn(d.params);
    }
  };
}

function collect() {
  const add = (kind, text, url) => findings.console.push({ step: curStep, kind, text, url: url || "" });
  on("Runtime.consoleAPICalled", (p) => add(p.type, p.args.map((a) => a.value ?? a.description ?? "").join(" ")));
  on("Log.entryAdded", (p) => add("log-" + p.entry.level, p.entry.text, p.entry.url));
  on("Runtime.exceptionThrown", (p) => findings.exceptions.push({ step: curStep, text: p.exceptionDetails.exception?.description || p.exceptionDetails.text }));
  on("Network.requestWillBeSent", (p) => {
    let u; try { u = new URL(p.request.url); } catch { return; }
    if (["http:", "https:", "ws:", "wss:"].includes(u.protocol) && u.hostname !== "127.0.0.1") findings.external.push({ step: curStep, url: p.request.url });
    reqLog.push(p.request.url);
  });
  on("Network.loadingFailed", (p) => findings.netfail.push({ step: curStep, text: p.errorText + (p.blockedReason ? " " + p.blockedReason : "") }));
  on("Page.javascriptDialogOpening", (p) => { dialogs.push(p.message); send("Page.handleJavaScriptDialog", { accept: true }).catch(() => {}); });
  on("Runtime.bindingCalled", (p) => { if (p.name === "rkCsp") findings.csp.push({ step: curStep, text: p.payload }); });
}

async function main() {
  const fx = await setupFixture();
  await setupBrowser();
  collect();
  for (const d of ["Runtime", "Page", "Log", "Network"]) await send(d + ".enable");
  await send("Runtime.addBinding", { name: "rkCsp" });
  await send("Page.addScriptToEvaluateOnNewDocument", {
    source: "document.addEventListener('securitypolicyviolation',function(e){window.rkCsp(e.violatedDirective+' '+e.blockedURI);});" });
  await send("Emulation.setFocusEmulationEnabled", { enabled: true });
  await send("Emulation.setDeviceMetricsOverride", { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });
  await send("Page.navigate", { url: fx.url + "/" });
  await waitFor("document.readyState === 'complete'", 15000, "page load");

  const aid = fx.agent_id;
  const statusCell = () => ev("(function(){var r=document.querySelector('#agents tbody tr');return r?r.children[3].textContent:null;})()");
  const clickBtn = (id) => ev("document.getElementById(" + q(id) + ").click(); true");
  const clickText = (scope, text) => ev("Array.from(document.querySelectorAll(" + q(scope + " button") + ")).filter(function(b){return b.textContent===" + q(text) + "})[0].click(); true");
  const login = (tok, name) => ev("(function(){var t=document.getElementById('tok'),o=document.getElementById('opn');" +
    "t.value=" + q(tok) + ";t.dispatchEvent(new Event('input',{bubbles:true}));" +
    "o.value=" + q(name) + ";o.dispatchEvent(new Event('input',{bubbles:true}));" +
    "document.getElementById('loginform').requestSubmit();})()");
  const expanded = (id) => "document.getElementById('" + id + "').getAttribute('aria-expanded')==='true'";

  await step("a. token prompt and wrong token", async () => {
    check(await ev("!document.getElementById('login').hidden && document.getElementById('app').hidden"), "token prompt not shown");
    check((await body()).includes("Operator token"), "no 'Operator token' label");
    await shot("1-token-prompt");
    await login("wrong-token", "tester");
    await waitFor("document.getElementById('loginmsg').textContent.length>0 && !document.getElementById('login').hidden", 10000, "error on the prompt");
    const msg = await ev("document.getElementById('loginmsg').textContent");
    check(/rejected|401/.test(msg), "unexpected error text: " + msg);
    check(await ev("document.getElementById('app').hidden"), "app visible after wrong token");
  });

  await step("b. right token: version and agent waiting for pairing", async () => {
    await login(fx.operator_token, "Tester");
    await waitFor("document.querySelector('#agents tbody tr')", 10000, "agents row");
    const v = await ev("document.getElementById('ver').textContent");
    check(/version: \S+/.test(v) && !v.includes("unknown"), "header version: " + v);
    check((await statusCell()) === "waiting for pairing", "state: " + await statusCell());
    check((await body()).includes(aid), "agent id not listed");
    await shot("2-agents-table");
  });

  await step("c. pairing input survives auto-refresh; Pair", async () => {
    check(/^[A-HJ-NP-Z2-9]{5}-[A-HJ-NP-Z2-9]{5}$/.test(fx.pairing_code), "pairing code format: " + fx.pairing_code);
    // typed the way people do: lower case, no dash (the input also takes the dashed form: 11 characters)
    const typed = fx.pairing_code.replace("-", "").toLowerCase();
    const half = typed.slice(0, 3), rest = typed.slice(3);
    const inp = "document.getElementById('pc-" + aid + "')";
    const attrs = await ev("(function(){var i=" + inp + ";return [i.maxLength,i.autocomplete,i.getAttribute('autocapitalize'),i.spellcheck];})()");
    check(attrs[0] === 11 && attrs[1] === "off" && attrs[2] === "characters" && attrs[3] === false, "pairing input attributes: " + q(attrs));
    await ev("(function(){var i=" + inp + ";i.value=" + q(fx.pairing_code) + ";})()");
    check((await ev(inp + ".value")) === fx.pairing_code, "the dashed code (11 characters) was cut: " + await ev(inp + ".value"));
    await ev("(function(){var i=" + inp + ";i.value='';})()");
    await ev("(function(){var i=" + inp + ";i.focus();i.value=" + q(half) + ";i.dispatchEvent(new Event('input',{bubbles:true}));})()");
    const before = reqLog.filter((u) => u.endsWith("/api/v1/agents")).length;
    await sleep(6000);
    const after = reqLog.filter((u) => u.endsWith("/api/v1/agents")).length;
    check(after > before, "no auto-refresh request seen in 6 s");
    check((await ev(inp + ".value")) === half, "half-typed value lost: " + await ev(inp + ".value"));
    check(await ev("document.activeElement===" + inp), "input lost focus");
    await ev("(function(){var i=" + inp + ";i.value=i.value+" + q(rest) + ";i.dispatchEvent(new Event('input',{bubbles:true}));})()");
    await clickText("#agents", "Pair");
    await waitFor("document.querySelector('#agents tbody tr td:nth-child(4)').textContent==='paired'", 10000, "state paired");
  });

  await step("d. open agent: status before scan", async () => {
    await clickText("#agents", "Open");
    await waitFor("document.querySelector('#agentstatus table')", 15000, "status table");
    const cells = await ev("Array.from(document.querySelectorAll('#agentstatus table tr')).map(function(r){return Array.from(r.children).map(function(c){return c.textContent;});})");
    check(cells.length === 2, "status table rows: " + q(cells));
    const h = cells[0], v = cells[1];
    check(v[h.indexOf("Environment")].length > 0, "environment empty");
    check(v[h.indexOf("Scanned")] === "no", "Scanned is " + v[h.indexOf("Scanned")]);
  });

  await step("e. run scan", async () => {
    await ev("(function(){function s(id,v){var e=document.getElementById(id);e.value=v;e.dispatchEvent(new Event('input',{bubbles:true}));e.dispatchEvent(new Event('change',{bubbles:true}));}" +
      "s('f-ticket','4242');s('f-symptom','repair_loop');})()");
    await clickBtn("b-scan");
    check(await ev("document.getElementById('b-scan').disabled"), "scan button not disabled while running");
    await sleep(1500);
    check(/Elapsed: \d+ s/.test(await ev("document.getElementById('scanmsg').textContent")), "no elapsed time shown");
    await waitFor("document.getElementById('scanmsg').textContent.indexOf('Scan finished')===0 || document.getElementById('scanmsg').className==='err'", 180000, "scan end");
    const m = await ev("document.getElementById('scanmsg').textContent");
    check(m === "Scan finished.", m);
    check(!(await ev("document.getElementById('b-scan').disabled")), "scan button still disabled");
    const rows = (await ev("document.querySelectorAll('#scanout table')[0].querySelectorAll('tr').length")) - 1;
    check(rows >= 15, "only " + rows + " section rows");
    check(/\bok\b/.test(await ev("document.getElementById('scanout').innerText")), "no 'ok' in scan table");
    await shot("3-after-scan");
  });

  await step("h. XSS probe through operator answers", async () => {
    const payload = "<img src=x onerror=window.__xss=1><script>window.__xss=1</script>";
    const r = await fetch(fx.url + "/api/v1/agents/" + aid + "/api/answers", { method: "POST",
      headers: { Authorization: "Bearer " + fx.operator_token, "X-RK-Operator": "Tester", "Content-Type": "application/json" },
      body: JSON.stringify({ symptom_text: payload }) });
    check(r.status === 200, "answers POST gave HTTP " + r.status + " " + (await r.text()).slice(0, 200));
    const imgs = await ev("document.images.length"), scripts = await ev("document.scripts.length");
    for (const b of ["b-sugg", "b-report", "b-log"]) {
      await clickBtn(b);
      await waitFor(expanded(b), 30000, b + " view");
    }
    await clickText("#agents", "Open");
    await waitFor("document.querySelector('#agentstatus table')", 15000, "status reload");
    await sleep(500);
    check((await ev("typeof window.__xss")) === "undefined", "window.__xss was set");
    check((await ev("document.images.length")) === imgs, "an <img> appeared");
    check((await ev("document.scripts.length")) === scripts, "a <script> appeared");
    check((await ev("document.querySelectorAll('img[src=\"x\"]').length")) === 0, "probe img in DOM");
    await clickBtn("b-report");
    await waitFor("document.querySelector('#detail pre')", 30000, "report view");
    check((await ev("document.querySelector('#detail pre').textContent")).includes("img src"), "payload text (escaped by the report generator) not shown in report");
  });

  await step("f. report, suggestions, steps, audit, files, log findings", async () => {
    await clickBtn("b-report");
    await waitFor("document.querySelector('#detail pre')", 30000, "report");
    check((await ev("document.getElementById('detail').innerText")).includes("Confirmed facts"), "report lacks 'Confirmed facts'");
    await shot("4-report-view");
    await clickBtn("b-sugg");
    await waitFor("document.querySelector('#detail ol li')", 30000, "suggestions");
    check((await ev("document.getElementById('detail').innerText")).includes("Because:"), "no 'Because:' line");
    await clickBtn("b-steps");
    await waitFor("document.getElementById('detail').innerText.includes('Blockers')", 30000, "steps");
    const t = await ev("document.getElementById('detail').innerText");
    check(t.includes("run at the target's console"), "console sentence missing");
    check((await ev("document.querySelectorAll('#detail button').length")) === 0, "a button exists in the steps view");
    await clickBtn("b-audit");
    await waitFor("document.querySelectorAll('#detail table tr').length>1", 30000, "audit rows");
    await clickBtn("b-files");
    await waitFor("document.querySelector('#detail ul')", 30000, "files");
    check((await ev("document.getElementById('detail').innerText")).includes("report.md"), "report.md not listed");
    await clickText("#detail", "report.md");
    await waitFor("document.querySelector('#detail pre') && document.querySelector('#detail pre').textContent.length>20", 30000, "file text");
    await clickBtn("b-log");
    await waitFor(expanded("b-log"), 30000, "log findings");
    const lt = await ev("document.getElementById('detail').innerText");
    check(/not collected|Flagged entries|None\./.test(lt) || lt.includes("Log findings"), "log findings empty");
  });

  await step("g. fetch bundle and stored cases", async () => {
    await clickBtn("b-fetch");
    await waitFor("document.getElementById('detail').innerText.includes('SHA-256')", 60000, "bundle table");
    const t = await ev("document.getElementById('detail').innerText");
    check(/Stored path\s+\S+/.test(t) && /[0-9a-f]{64}/.test(t), "stored path / sha256 missing");
    await clickBtn("b-cases");
    await waitFor("document.getElementById('cases').innerText.includes('ITW-4242-')", 15000, "case list");
    const heads = await ev("Array.from(document.querySelectorAll('#cases th')).map(function(h){return h.textContent;})");
    check(heads.includes("Device ID"), "no Device ID column");
    await shot("5-stored-cases");
  });

  await step("dark mode screenshot", async () => {
    await send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: "dark" }] });
    await sleep(300);
    check(await ev("matchMedia('(prefers-color-scheme: dark)').matches"), "dark media not applied");
    await shot("6-dark-cases");
    await send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: "light" }] });
  });

  await step("i. revoke", async () => {
    await clickText("#agents", "Revoke");
    await waitFor("document.querySelector('#agents tbody tr td:nth-child(4)').textContent==='revoked'", 15000, "state revoked");
    check(dialogs.length === 1 && dialogs[0].includes(aid), "confirm dialog not seen: " + q(dialogs));
  });

  await step("j. forget token", async () => {
    await clickBtn("forget");
    check(await ev("!document.getElementById('login').hidden && document.getElementById('app').hidden"), "prompt not shown");
    check((await ev("sessionStorage.length")) === 0, "sessionStorage not empty");
  });
}

function summary() {
  console.log("\n=== SMOKE SUMMARY ===");
  for (const [n, ok, why] of results) console.log((ok ? "PASS " : "FAIL ") + n + (ok ? "" : "  -> " + why));
  // Expected: the deliberate wrong-token request makes Edge log one "401" resource error in step a.
  const unexpected = findings.console.filter((c) => !(c.step.startsWith("a.") && /401/.test(c.text)));
  console.log("console messages: " + findings.console.length + " (unexpected: " + unexpected.length + ")");
  unexpected.forEach((c) => console.log("  [" + c.step + "] " + c.kind + ": " + c.text + " " + c.url));
  console.log("uncaught exceptions: " + findings.exceptions.length);
  findings.exceptions.forEach((c) => console.log("  [" + c.step + "] " + c.text));
  console.log("failed network requests: " + findings.netfail.length);
  findings.netfail.forEach((c) => console.log("  [" + c.step + "] " + c.text));
  console.log("requests to hosts other than 127.0.0.1: " + findings.external.length);
  findings.external.forEach((c) => console.log("  [" + c.step + "] " + c.url));
  console.log("CSP violations: " + findings.csp.length);
  findings.csp.forEach((c) => console.log("  [" + c.step + "] " + c.text));
  console.log("screenshots: " + OUT);
  return results.length > 0 && results.every((r) => r[1]) && !unexpected.length && !findings.exceptions.length &&
    !findings.netfail.length && !findings.external.length && !findings.csp.length;
}

let ok = false;
try { await main(); } catch (e) { results.push([curStep + " (fatal)", false, e.stack || String(e)]); }
finally {
  try { ok = summary(); } catch (e) { console.log(String(e)); }
  try { ws?.close(); } catch { /* ignore */ }
  try { edge?.kill(); } catch { /* ignore */ }
  try { fixture?.stdin.end(); } catch { /* ignore */ }
  await sleep(1500);
  try { fixture?.kill(); } catch { /* ignore */ }
  if (edge && process.platform === "win32") spawn("taskkill", ["/PID", String(edge.pid), "/T", "/F"], { stdio: "ignore" });
  await sleep(1500);
  try { if (edgeDir) rmSync(edgeDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 300 }); } catch { /* ignore */ }
}
process.exit(ok ? 0 : 1);
