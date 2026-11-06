"""The get-checks purchase page (dashboard/credits-page/index.html).

The page is a standalone static file the exporter copies verbatim to
get-checks/index.html, so these tests read the source directly. The
copy assertions pin the 2026-10-29 fixes Bayo ordered after testing
the live page: no per-check pricing, no desktop-app copy, the Pass
card speaks only about the Pass, and the checks code is explained
before the offers. The behavior tests run the page's real script
under Node with fetch / window / document stubbed, and pin the buy
flow: checkout opens in a new tab, this page never navigates, and the
clicked button always gets its original label back.
"""
import os
import re
import shutil
import subprocess
import tempfile
import unittest

DASH = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOURCE = os.path.join(DASH, "credits-page", "index.html")


def _read_source():
    with open(SOURCE, encoding="utf-8") as f:
        return f.read()


class CreditsPageCopyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.src = _read_source()
        cls.lower = cls.src.lower()

    def test_no_per_check_pricing(self):
        self.assertNotIn("cents a check", self.lower)
        self.assertNotIn("percheck", self.lower)

    def test_no_desktop_or_layers_language(self):
        self.assertNotIn("desktop", self.lower)
        self.assertNotIn("verification layers", self.lower)

    def test_pass_card_speaks_only_about_the_pass(self):
        self.assertIn("function renderPass(p, data, box)", self.src)
        self.assertNotIn("biggest pack", self.lower)
        self.assertNotIn("contrast", self.lower)

    def test_pack_cards_keep_price_and_plain_terms(self):
        self.assertIn("One payment, no subscription.", self.src)

    def test_the_code_is_explained_upfront(self):
        for phrase in ("Paste the code into the extension",
                       "not a referral code",
                       "personal referral link",
                       "receipt and a backup"):
            self.assertIn(phrase, self.src)

    def test_buy_flow_shape(self):
        # a blank tab opens inside the click; checkout loads into it
        self.assertIn('window.open("", "_blank")', self.src)
        self.assertIn("tab.location.href = res.j.checkout_url", self.src)
        self.assertIn("tab.close()", self.src)
        # the button always gets the label it had before the click
        self.assertIn("var originalLabel = btn.textContent", self.src)
        self.assertIn("btn.textContent = originalLabel", self.src)
        # the page itself never navigates away to checkout (the old
        # code assigned the bare location; tab.location is fine)
        self.assertIsNone(re.search(
            r"(?<![\w.])location\.href\s*=\s*res\.j\.checkout_url",
            self.src))
        # the old failure path overwrote every button's label with
        # "Buy <pack>", which corrupted the Pass button's label
        self.assertNotIn('"Buy " + pack.label', self.src)

    def test_no_em_dashes(self):
        self.assertNotIn("—", self.src)


HARNESS = r"""
const scenario = process.argv[2];
const failures = [];
function check(name, cond) { if (!cond) failures.push(name); }

class ClassList {
  constructor() { this.set = new Set(); }
  add(c) { this.set.add(c); }
  remove(c) { this.set.delete(c); }
  contains(c) { return this.set.has(c); }
}
class El {
  constructor(tag) {
    this.tagName = String(tag || "div").toUpperCase();
    this.children = [];
    this.className = "";
    this.disabled = false;
    this.value = "";
    this.type = "";
    this._text = "";
    this._html = "";
    this._listeners = {};
    this.classList = new ClassList();
  }
  set textContent(v) { this._text = String(v); }
  get textContent() { return this._text; }
  set innerHTML(v) { this._html = String(v); if (v === "") this.children = []; }
  get innerHTML() { return this._html; }
  appendChild(c) { this.children.push(c); return c; }
  addEventListener(name, fn) {
    (this._listeners[name] = this._listeners[name] || []).push(fn);
  }
  click() { (this._listeners.click || []).slice().forEach((fn) => fn.call(this)); }
}
function hiddenEl(tag) { const e = new El(tag); e.classList.add("hidden"); return e; }
const byId = {
  "email": new El("input"),
  "packs": new El("div"),
  "checkout-off": hiddenEl("div"),
  "shop-error": hiddenEl("div"),
  "success": hiddenEl("div"),
  "code-box": new El("div"),
  "copy-btn": hiddenEl("button")
};
global.document = {
  getElementById: (id) => byId[id] || null,
  createElement: (tag) => new El(tag)
};
global.location = { search: "", href: "https://verify.npclabs.xyz/get-checks" };
const PAGE_URL = global.location.href;

const openCalls = [];
let lastTab = null;
global.window = {
  open: function (url, target) {
    openCalls.push({ url: url, target: target });
    if (scenario === "blocked") { lastTab = null; return null; }
    lastTab = { location: { href: "" }, closed: false,
                close: function () { this.closed = true; } };
    return lastTab;
  }
};

const PACKS = {
  checkout_available: true,
  packs: [
    { id: "verifier-pass", kind: "access", label: "Verifier Pass",
      price_cents: 2500, currency: "usd", on_sale: true,
      registry_unlimited: true, ai_checks: 400, checks: 0 },
    { id: "checks-100", kind: "pack", label: "100 checks",
      price_cents: 900, currency: "usd", on_sale: true, checks: 100 },
    { id: "checks-250", kind: "pack", label: "250 checks",
      price_cents: 1900, currency: "usd", on_sale: true, checks: 250 }
  ]
};
const CHECKOUT_URL = "https://checkout.stripe.com/pay/cs_test_123";
global.fetch = function (url) {
  if (url.indexOf("/v1/credits/packs") >= 0) {
    return Promise.resolve({ status: 200,
                             json: () => Promise.resolve(PACKS) });
  }
  if (url.indexOf("/v1/credits/checkout") >= 0) {
    if (scenario === "netfail") return Promise.reject(new Error("network down"));
    if (scenario === "httpfail") {
      return Promise.resolve({ status: 500, json: () => Promise.resolve({}) });
    }
    return Promise.resolve({ status: 201,
                             json: () => Promise.resolve({ checkout_url: CHECKOUT_URL }) });
  }
  return Promise.reject(new Error("unexpected fetch: " + url));
};

/*__PAGE_SCRIPT__*/

async function flush() {
  for (let i = 0; i < 12; i++) await new Promise((r) => setImmediate(r));
}

(async function () {
  await flush();
  const cards = byId.packs.children;
  check("three cards render", cards.length === 3);
  const buttons = cards.map((c) => c.children.find((k) => k.tagName === "BUTTON"));
  check("every card has a buy button", buttons.every(Boolean));
  const passBtn = buttons[0], packBtn = buttons[1];
  check("pass button label", passBtn.textContent === "Start the Verifier Pass");
  check("pack button label", packBtn.textContent === "Buy 100 checks");
  check("pass card carries no pack details",
        cards[0].innerHTML.indexOf("250 checks") < 0 &&
        cards[0].innerHTML.indexOf("$19") < 0 &&
        cards[0].innerHTML.indexOf("biggest") < 0);
  check("pass card has no desktop copy",
        cards[0].innerHTML.toLowerCase().indexOf("desktop") < 0);
  check("pack card has no per-check pricing",
        cards[1].innerHTML.indexOf("cents") < 0);
  check("pack card keeps its terms line",
        cards[1].innerHTML.indexOf("One payment, no subscription.") >= 0);

  const before = openCalls.length;
  passBtn.click();
  check("click disables the button", passBtn.disabled === true);
  check("click shows the opening label",
        passBtn.textContent === "Opening checkout...");
  check("tab open attempted synchronously in the click",
        openCalls.length === before + 1 && openCalls[before].url === "" &&
        openCalls[before].target === "_blank");
  await flush();
  check("button re-enabled after the flow", passBtn.disabled === false);
  check("button label restored to the original",
        passBtn.textContent === "Start the Verifier Pass");
  check("page itself never navigated", global.location.href === PAGE_URL);
  if (scenario === "success") {
    check("checkout opened in the new tab",
          !!lastTab && lastTab.location.href === CHECKOUT_URL);
    check("tab left open on success", !!lastTab && lastTab.closed === false);
    check("no error notice shown",
          byId["shop-error"].classList.contains("hidden"));
    packBtn.click();
    check("pack click shows the opening label",
          packBtn.textContent === "Opening checkout...");
    await flush();
    check("pack button label restored",
          packBtn.textContent === "Buy 100 checks");
    check("pack checkout opened in its own tab",
          !!lastTab && lastTab.location.href === CHECKOUT_URL);
  } else if (scenario === "blocked") {
    check("fallback open used the checkout address",
          openCalls.length === before + 2 &&
          openCalls[before + 1].url === CHECKOUT_URL);
  } else if (scenario === "httpfail") {
    check("blank tab closed after checkout refused",
          !!lastTab && lastTab.closed === true);
    check("checkout-off notice shown",
          !byId["checkout-off"].classList.contains("hidden"));
  } else if (scenario === "netfail") {
    check("blank tab closed after network failure",
          !!lastTab && lastTab.closed === true);
    check("shop-error notice shown",
          !byId["shop-error"].classList.contains("hidden"));
  }

  if (failures.length) {
    console.log("FAIL " + scenario + ": " + failures.join(" | "));
    process.exit(1);
  }
  console.log("OK " + scenario);
})().catch((e) => {
  console.log("ERROR " + scenario + ": " + (e && e.stack || e));
  process.exit(2);
});
"""


@unittest.skipUnless(shutil.which("node"),
                     "node is required for the credits page behavior tests")
class CreditsPageBehaviorTest(unittest.TestCase):
    def test_buy_flow_in_node(self):
        src = _read_source()
        m = re.search(r"<script>(.*?)</script>", src, re.DOTALL)
        self.assertIsNotNone(m, "credits page carries no script block")
        harness = HARNESS.replace("/*__PAGE_SCRIPT__*/", m.group(1))
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "harness.js")
            with open(path, "w", encoding="utf-8") as f:
                f.write(harness)
            for scenario in ("success", "httpfail", "netfail", "blocked"):
                proc = subprocess.run(
                    ["node", path, scenario],
                    capture_output=True, text=True, timeout=60)
                self.assertEqual(
                    proc.returncode, 0,
                    "%s: %s%s" % (scenario, proc.stdout, proc.stderr))


if __name__ == "__main__":
    unittest.main()
