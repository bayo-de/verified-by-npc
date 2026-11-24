/* Page-level tests for the Biblo chat widget fixes (Node + jsdom).
 *
 * Run: node --test dashboard/tests/chat_widget.test.js
 * (needs the jsdom package and python3; tests skip cleanly when
 * jsdom is not installed.)
 *
 * Pins, in the real rendered home page: the panel starts closed,
 * the launcher opens it, the close button and Escape collapse it
 * back to the launcher, the open or closed choice is restored
 * from localStorage on a fresh load, closing never wipes the
 * conversation, the input placeholder is complete, and a sources
 * list carrying an internal error label renders without it.
 */
"use strict";

const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync } = require("node:child_process");

let JSDOM = null;
try { ({ JSDOM } = require("jsdom")); } catch (e) { /* skip */ }

let homeHtml = null;
function loadHome() {
  if (homeHtml) return homeHtml;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "npc-chat-"));
  execFileSync("python3", [
    path.join(__dirname, "render_fixtures.py"), dir
  ], { stdio: "pipe" });
  homeHtml = fs.readFileSync(path.join(dir, "home.html"), "utf8");
  return homeHtml;
}

function jsonRes(status, body) {
  return { ok: status >= 200 && status < 300, status,
           json: async () => body };
}

function loadChat(opts) {
  opts = opts || {};
  const dom = new JSDOM(loadHome(), {
    url: "https://verify.example/",
    runScripts: "dangerously",
    pretendToBeVisual: true,
    beforeParse(window) {
      if (opts.savedOpen !== undefined) {
        try {
          window.localStorage.setItem(
            "npc-chat-open", opts.savedOpen ? "1" : "0");
        } catch (e) { /* storage unavailable in this window */ }
      }
      window.fetch = async (url, init) => {
        if (String(url).endsWith("/v1/chat/feedback")) {
          return jsonRes(200, {});
        }
        if (String(url).endsWith("/v1/chat")) {
          return jsonRes(200, {
            thread_id: "thread_1",
            reply: "Registration is the first step.",
            state: "on",
            sources: [
              { title: "How it works", path: "/help" },
              { title: "Meta Muse: unable to verify", path: "/help" },
              { title: "Register your work", path: "/verify" }
            ]
          });
        }
        return jsonRes(200, {});
      };
      window.HTMLElement.prototype.scrollIntoView = function () {};
    }
  });
  return dom;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function panelOf(dom) {
  return dom.window.document.getElementById("npc-chat-float");
}
function btnOf(dom) {
  return dom.window.document.getElementById("npc-chat-btn");
}

test("fresh load starts closed, launcher opens, close collapses",
  { skip: !JSDOM }, async () => {
    const dom = loadChat({});
    await sleep(150);
    const panel = panelOf(dom), btn = btnOf(dom);
    assert.strictEqual(panel.hidden, true, "panel starts hidden");
    assert.strictEqual(
      dom.window.getComputedStyle(panel).display, "none",
      "the [hidden] rule makes the closed panel invisible");
    assert.strictEqual(btn.getAttribute("aria-expanded"), "false");
    btn.click();
    assert.strictEqual(panel.hidden, false, "launcher opens");
    assert.strictEqual(btn.getAttribute("aria-expanded"), "true");
    assert.strictEqual(
      dom.window.localStorage.getItem("npc-chat-open"), "1");
    panel.querySelector(".npc-chat-close").click();
    assert.strictEqual(panel.hidden, true, "close button collapses");
    assert.strictEqual(btn.getAttribute("aria-expanded"), "false");
    assert.strictEqual(
      dom.window.localStorage.getItem("npc-chat-open"), "0");
  });

test("Escape closes an open panel",
  { skip: !JSDOM }, async () => {
    const dom = loadChat({});
    await sleep(150);
    btnOf(dom).click();
    assert.strictEqual(panelOf(dom).hidden, false);
    dom.window.document.dispatchEvent(
      new dom.window.KeyboardEvent("keydown",
        { key: "Escape", bubbles: true }));
    assert.strictEqual(panelOf(dom).hidden, true);
  });

test("a saved open state is restored on a fresh load",
  { skip: !JSDOM }, async () => {
    const dom = loadChat({ savedOpen: true });
    await sleep(150);
    assert.strictEqual(panelOf(dom).hidden, false);
    assert.strictEqual(btnOf(dom).getAttribute("aria-expanded"), "true");
    const dom2 = loadChat({ savedOpen: false });
    await sleep(150);
    assert.strictEqual(panelOf(dom2).hidden, true);
  });

test("closing keeps the conversation, and sources are customer safe",
  { skip: !JSDOM }, async () => {
    const dom = loadChat({});
    await sleep(150);
    const doc = dom.window.document;
    btnOf(dom).click();
    const panel = panelOf(dom);
    const input = panel.querySelector(".npc-chat-form input");
    assert.strictEqual(input.getAttribute("placeholder"),
      "Ask about records or verification");
    input.value = "How do I register?";
    panel.querySelector(".npc-chat-form").dispatchEvent(
      new dom.window.Event("submit", { bubbles: true, cancelable: true }));
    await sleep(300);
    const log = panel.querySelector(".npc-chat-log");
    assert.match(log.textContent, /Registration is the first step/);
    assert.match(log.textContent, /How it works/);
    assert.match(log.textContent, /Register your work/);
    assert.ok(!/Meta Muse/.test(log.textContent),
      "the internal label never renders");
    assert.ok(!/unable to verify/i.test(log.textContent),
      "the error label never renders");
    const links = log.querySelectorAll(".srcs a");
    assert.strictEqual(links.length, 2, "only safe sources render");
    panel.querySelector(".npc-chat-close").click();
    assert.strictEqual(panel.hidden, true);
    btnOf(dom).click();
    assert.strictEqual(panel.hidden, false);
    assert.match(panel.querySelector(".npc-chat-log").textContent,
      /Registration is the first step/,
      "the conversation survives the close and reopen cycle");
  });
