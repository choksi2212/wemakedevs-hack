// Behavior spot-check: extract the live api() helper from index.html verbatim
// and drive it with stubbed fetch responses (502 HTML / 502 empty / 200 empty /
// 422 JSON detail), asserting the operator-facing error messages.
const fs = require("fs");
const html = fs.readFileSync("sever/console/static/index.html", "utf8");
const start = html.indexOf("async function api(path, opts)");
const end = html.indexOf("\n  }", html.indexOf("return body;", start));
const fnText = html.slice(start, end + 4);
const api = new Function(fnText + "\nreturn api;")();
(async () => {
  let out = [];
  global.fetch = async () => ({ ok: false, status: 502, text: async () => '<!DOCTYPE html><html lang="en"><head>' });
  try { await api("/api/finding"); } catch (e) { out.push(["502+HTML", e.message]); }
  global.fetch = async () => ({ ok: false, status: 503, text: async () => "" });
  try { await api("/api/finding"); } catch (e) { out.push(["503+empty", e.message]); }
  global.fetch = async () => ({ ok: false, status: 502, text: async () => "plain text body" });
  try { await api("/x"); } catch (e) { out.push(["502+plaintext", e.message]); }
  global.fetch = async () => ({ ok: true, status: 200, text: async () => "" });
  try { await api("/api/state"); } catch (e) { out.push(["200+empty", e.message]); }
  global.fetch = async () => ({ ok: false, status: 422, text: async () => JSON.stringify({ detail: [{ msg: "bad" }] }) });
  try { await api("/api/finding"); } catch (e) { out.push(["422+detail(list)", e.message]); }
  global.fetch = async () => ({ ok: true, status: 200, text: async () => JSON.stringify({ ok: true }) });
  const r = await api("/api/plan");
  out.push(["200+json", JSON.stringify(r)]);
  for (const [k, v] of out) console.log(k.padEnd(16), "->", v);
  const htmlLeak = out.some(([, v]) => v.includes("<!DOCTYPE") || v.includes("<html"));
  console.log(htmlLeak ? "FAIL: raw HTML leaks into error message" : "PASS: no raw HTML ever surfaces");
  if (!out[0][1].includes("server error 502")) throw new Error("502 HTML guard copy missing");
  if (!out[3][1].includes("empty/malformed")) throw new Error("empty-200 guard copy missing");
  console.log("PASS: guard copy correct");
})();
