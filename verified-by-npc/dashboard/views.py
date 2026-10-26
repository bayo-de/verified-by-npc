"""HTML views for the Verified by NPC dashboard.

Restrained, quiet pages: system type, hairline rules, small-caps labels.
Copy explains the why, never the internal method. No em-dashes anywhere
in user-facing text. Every API-derived value is HTML-escaped at render.
"""
import html as _html
import os

CSS = """
:root{
  --ink:#181818; --muted:#6f6f6f; --faint:#9a9a9a;
  --line:#e6e6e4; --bg:#fbfbf9; --card:#ffffff;
  --ok:#1a7a3c; --okbg:#eef7f0;
  --warn:#8f5e00; --warnbg:#faf4e3;
  --bad:#b02318; --badbg:#fbeeee;
  --unk:#6f6f6f; --unkbg:#f2f2f1;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font-family:-apple-system,BlinkMacSystemFont,"SF Pro Text",Inter,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  font-size:16px;line-height:1.6;-webkit-font-smoothing:antialiased}
.wrap{max-width:760px;margin:0 auto;padding:0 24px}
.top{border-bottom:1px solid var(--line);background:var(--card)}
.top-in{display:flex;align-items:baseline;justify-content:space-between;flex-wrap:wrap;padding-top:18px;padding-bottom:18px;gap:12px}
.brand{color:var(--ink);text-decoration:none;font-weight:650;font-size:17px;letter-spacing:-0.01em}
nav a{color:var(--muted);text-decoration:none;font-size:14px;margin-left:20px}
nav a:hover{color:var(--ink)}
@media(max-width:640px){nav{display:flex;flex-wrap:wrap;gap:8px 18px}nav a{margin-left:0}}
main.wrap{padding:72px 24px 64px}
h1{font-size:32px;line-height:1.25;letter-spacing:-0.02em;font-weight:650;margin:0 0 12px}
h2{font-size:20px;font-weight:650;letter-spacing:-0.01em;margin:40px 0 10px}
.kicker{font-size:12px;letter-spacing:.14em;text-transform:uppercase;color:var(--faint);margin:0 0 10px}
.lede{font-size:18px;color:var(--muted);max-width:34em;margin:0 0 8px}
p{max-width:38em}
a{color:var(--ink)}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:20px 22px;margin:16px 0}
.card h3{margin:0 0 6px;font-size:17px;font-weight:650}
.card p{margin:6px 0 0;color:var(--muted);font-size:15px}
.row{display:grid;grid-template-columns:1fr 1fr;gap:14px}
@media(max-width:640px){.row{grid-template-columns:1fr}}
.pill{display:inline-block;font-size:11.5px;font-weight:650;letter-spacing:.08em;text-transform:uppercase;
  padding:3px 11px;border-radius:999px;border:1px solid var(--line);background:var(--unkbg);color:var(--unk);white-space:nowrap}
.pill.verified{color:var(--ok);background:var(--okbg);border-color:#cfe8d6}
.pill.caveats{color:var(--warn);background:var(--warnbg);border-color:#e9d9ab}
.pill.bad{color:var(--bad);background:var(--badbg);border-color:#efc9c4}
table{width:100%;border-collapse:collapse;margin:18px 0;font-size:14.5px}
th{text-align:left;font-size:11.5px;letter-spacing:.1em;text-transform:uppercase;color:var(--faint);
  font-weight:650;padding:10px 12px;border-bottom:1px solid var(--line)}
td{padding:12px;border-bottom:1px solid var(--line);vertical-align:top}
td.dim{color:var(--muted)}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px;word-break:break-all}
.keybox{background:#f4f4f2;border:1px solid var(--line);border-radius:8px;padding:12px 14px;margin:8px 0}
form.lookup{display:flex;gap:10px;margin:18px 0;flex-wrap:wrap}
input[type=text]{flex:1;min-width:200px;padding:11px 14px;font-size:15px;border:1px solid var(--line);
  border-radius:10px;background:var(--card);color:var(--ink)}
textarea{width:100%;min-height:88px;padding:11px 14px;font-size:15px;border:1px solid var(--line);
  border-radius:10px;background:var(--card);color:var(--ink);font-family:inherit}
button{padding:11px 20px;font-size:15px;font-weight:600;border:0;border-radius:10px;background:var(--ink);color:#fff;cursor:pointer}
button:hover{opacity:.88}
button[disabled]{opacity:.5;cursor:default}
form.reg{max-width:560px}
form.reg input,form.reg select{width:100%;padding:11px 14px;font-size:15px;border:1px solid var(--line);
  border-radius:10px;background:var(--card);color:var(--ink)}
form.reg button{margin-top:18px}
.checklist{list-style:none;margin:10px 0;padding:0;font-size:14.5px}
.checklist li{padding:6px 0;border-bottom:1px solid var(--line);color:var(--muted)}
.checklist li strong{color:var(--ink);font-weight:650}
.steps{margin:14px 0;padding-left:22px}
.steps li{padding:6px 0;color:var(--muted)}
.steps li strong{color:var(--ink);font-weight:650}
label.small{font-size:13px;color:var(--muted);display:block;margin:14px 0 6px}
.kv{display:grid;grid-template-columns:170px 1fr;gap:6px 18px;margin:14px 0;font-size:15px}
.kv dt{color:var(--muted)}
.kv dd{margin:0}
.timeline{list-style:none;margin:14px 0;padding:0}
.timeline li{padding:10px 0 10px 18px;border-left:2px solid var(--line);margin-left:6px}
.timeline .ev{font-weight:650}
.timeline .at{color:var(--faint);font-size:13px}
.timeline .dt{color:var(--muted);font-size:14px}
.notice{border:1px solid var(--line);border-radius:12px;padding:18px 20px;background:var(--card);margin:18px 0}
.notice h3{margin:0 0 6px;font-size:16px}
.notice p{margin:4px 0 0;color:var(--muted);font-size:14.5px}
.foot{border-top:1px solid var(--line);padding:22px 0 40px;color:var(--faint);font-size:13px;display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px}
.foot a{color:var(--faint)}
.examples{font-size:14px;color:var(--muted);margin-top:10px}
.examples a{margin-right:14px}
.scope{margin:2px 0}
.scope span{display:inline-block;background:#f4f4f2;border:1px solid var(--line);border-radius:6px;
  padding:2px 9px;margin:0 6px 6px 0;font-size:13px;color:var(--muted)}
.npc-chat-btn{position:fixed;right:20px;bottom:20px;width:56px;height:56px;border-radius:50%;
  padding:0;border:1px solid var(--line);background:var(--card);box-shadow:0 6px 24px rgba(0,0,0,.16);z-index:60}
.npc-chat-btn img{width:100%;height:100%;border-radius:50%;display:block}
.npc-chat-panel{border:1px solid var(--line);border-radius:14px;background:var(--card);
  display:flex;flex-direction:column;overflow:hidden}
.npc-chat-panel.floating{position:fixed;right:20px;bottom:88px;width:min(360px,calc(100vw - 40px));
  height:min(520px,calc(100vh - 120px));box-shadow:0 12px 40px rgba(0,0,0,.18);z-index:60}
.npc-chat-panel.inline{height:520px;max-height:70vh;margin:16px 0}
.npc-chat-head{display:flex;align-items:baseline;justify-content:space-between;gap:8px;
  padding:14px 16px 10px;border-bottom:1px solid var(--line)}
.npc-chat-head .who{font-weight:650;font-size:16px}
.npc-chat-head .sub{color:var(--muted);font-size:12.5px;margin-left:8px}
.npc-chat-close{background:none;color:var(--muted);padding:4px 8px;font-size:18px;line-height:1}
.npc-chat-log{flex:1;overflow-y:auto;padding:14px 16px}
.npc-chat-msg{margin:0 0 14px}
.npc-chat-msg .from{font-size:11.5px;letter-spacing:.08em;text-transform:uppercase;color:var(--faint);margin:0 0 2px}
.npc-chat-msg p{margin:0;font-size:14.5px;white-space:pre-wrap;max-width:none}
.npc-chat-msg .srcs{font-size:12.5px;color:var(--muted);margin-top:5px}
.npc-chat-msg .srcs a{margin-right:10px}
.npc-chat-fb{margin-top:5px}
.npc-chat-fb button{background:none;color:var(--muted);padding:2px 8px 2px 0;font-size:14px}
.npc-chat-fb button[disabled]{opacity:.45}
.npc-chat-starters{padding:0 16px 10px;display:flex;flex-wrap:wrap;gap:8px}
.npc-chat-starters button{background:#f4f4f2;color:var(--ink);border:1px solid var(--line);
  font-size:13px;font-weight:500;padding:7px 12px;border-radius:999px}
.npc-chat-notice{padding:10px 16px;border-top:1px solid var(--line);color:var(--muted);font-size:12.5px}
.npc-chat-form{display:flex;gap:8px;padding:0 16px 14px}
.npc-chat-form input{flex:1;min-width:0;padding:10px 12px;font-size:14.5px;border:1px solid var(--line);
  border-radius:10px;background:var(--card);color:var(--ink)}
.npc-chat-form button{padding:10px 16px;font-size:14.5px}
.npc-keep-record{border-top:1px solid var(--line);margin-top:18px;padding-top:4px}
.npc-keep-record button{padding:6px 14px;font-size:13.5px}
"""


def esc(value):
    if value is None:
        return ""
    return _html.escape(str(value), quote=True)


# The public verification API base. The Verify yours forms and the
# live Search lookup talk to it from the visitor's browser. The local
# preview passes its own configured API URL instead; the static
# exporter rewrites that URL to this public base (see export_static).
PUBLIC_API_BASE = "https://api.npclabs.xyz"

# The Biblo chat widget (the floating button on every page, and the
# Ask Biblo section on /help) ships only when enabled. It stays
# enabled for the local preview and the test suite. The public
# restage of 2026-10-16 builds with it off (export_static's
# include_chat=False): chat activates only after Bayo places the
# API key and the full grounding eval passes, so until then the
# public site carries no chat affordance at all.
CHAT_WIDGET_ENABLED = True

# Verify yours page script. Plain browser JavaScript, no dependencies.
# Rules it lives by: it never fakes a submission or a result. If the
# verification service does not answer, the page says so plainly and
# the forms are disabled. Results render only from a real API answer,
# built with textContent so record data is never markup.
VERIFY_JS = """
(function () {
  var root = document.getElementById("npc-verify");
  if (!root || !window.fetch) return;
  var base = (root.getAttribute("data-api-base") || "").replace(/\\/+$/, "");
  var downBox = document.getElementById("npc-service-down");
  var statusLine = document.getElementById("npc-service-status");
  var resultBox = document.getElementById("npc-register-result");
  var errorBox = document.getElementById("npc-register-error");
  var errorText = document.getElementById("npc-register-error-text");
  var forms = [document.getElementById("npc-content-form"),
               document.getElementById("npc-agent-form")];
  function setDown() {
    if (downBox) downBox.hidden = false;
    if (statusLine) statusLine.textContent =
      "Registration is paused: the verification service is not " +
      "answering yet.";
    forms.forEach(function (f) {
      if (!f) return;
      var btns = f.querySelectorAll("button");
      for (var i = 0; i < btns.length; i++) btns[i].disabled = true;
    });
  }
  function showError(msg) {
    if (errorText) errorText.textContent = msg;
    if (errorBox) errorBox.hidden = false;
  }
  function el(tag, text) {
    var n = document.createElement(tag);
    if (text) n.textContent = text;
    return n;
  }
  function copyButton(label, value, cls) {
    var b = el("button", label);
    b.type = "button";
    b.className = cls;
    b.addEventListener("click", function () {
      function done() {
        b.textContent = "Copied";
        setTimeout(function () { b.textContent = label; }, 2000);
      }
      function fallback() {
        var ta = el("textarea");
        ta.value = value;
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        try { if (document.execCommand("copy")) done(); }
        catch (e) { /* the value stays on screen to copy by hand */ }
        document.body.removeChild(ta);
      }
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(value).then(done, fallback);
      } else {
        fallback();
      }
    });
    return b;
  }
  function keepBlock(rec) {
    var keep = el("div");
    keep.className = "npc-keep-record";
    keep.appendChild(el("h3", "Keep this record"));
    keep.appendChild(el("p",
      "Your NPC ID and the record link are how you, and anyone " +
      "you share them with, can find this record again. Save them " +
      "now: this page is the one place they are shown together."));
    var link = window.location.origin + "/search?id=" +
      encodeURIComponent(rec.record_id);
    var idRow = el("p");
    idRow.appendChild(el("span", "NPC ID: "));
    var idVal = el("span", rec.record_id);
    idVal.className = "mono";
    idRow.appendChild(idVal);
    idRow.appendChild(document.createTextNode(" "));
    idRow.appendChild(copyButton("Copy ID", rec.record_id,
                                 "npc-copy-id"));
    keep.appendChild(idRow);
    var linkRow = el("p");
    linkRow.appendChild(el("span", "Record link: "));
    var linkVal = el("span", link);
    linkVal.className = "mono";
    linkRow.appendChild(linkVal);
    linkRow.appendChild(document.createTextNode(" "));
    linkRow.appendChild(copyButton("Copy link", link,
                                   "npc-copy-link"));
    keep.appendChild(linkRow);
    var dlBtn = el("button", "Download the record");
    dlBtn.type = "button";
    dlBtn.className = "npc-download-record";
    dlBtn.addEventListener("click", function () {
      var blob = new Blob([JSON.stringify(rec, null, 2)],
                          {type: "application/json"});
      var url = URL.createObjectURL(blob);
      var a = el("a");
      a.href = url;
      a.download = rec.record_id + ".json";
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(function () { URL.revokeObjectURL(url); }, 5000);
    });
    var dlRow = el("p");
    dlRow.appendChild(dlBtn);
    dlRow.appendChild(el("span",
      " The signed record itself, as a file you can keep and " +
      "check anywhere."));
    keep.appendChild(dlRow);
    return keep;
  }
  function checkList(title, entries, field) {
    if (!entries || !entries.length) return null;
    var frag = document.createDocumentFragment();
    frag.appendChild(el("h3", title));
    var ul = document.createElement("ul");
    ul.className = "checklist";
    entries.forEach(function (c) {
      var li = el("li");
      var name = (c.check || "").replace(/_/g, " ");
      var detail = c[field] || c.reason ||
        (c.status ? String(c.status).replace(/_/g, " ") : "");
      var strong = el("strong", name);
      li.appendChild(strong);
      if (detail) li.appendChild(document.createTextNode(": " + detail));
      ul.appendChild(li);
    });
    frag.appendChild(ul);
    return frag;
  }
  function kyaText(v) {
    if (v === null || v === undefined) return "Not on this record.";
    if (Array.isArray(v)) return v.map(kyaText).join(", ");
    if (typeof v === "object") {
      return Object.keys(v).sort().filter(function (k) {
        return k !== "detail";
      }).map(function (k) {
        return k.replace(/_/g, " ") + ": " + kyaText(v[k]);
      }).join("; ");
    }
    return String(v);
  }
  function kyaBlock(kya) {
    if (!kya || typeof kya !== "object") return null;
    var frag = document.createDocumentFragment();
    frag.appendChild(el("h3", "Know Your Agent"));
    var dl = document.createElement("dl");
    dl.className = "kv";
    var rep = kya.reputation;
    var repText;
    if (rep && typeof rep === "object" && rep.state === "rated") {
      var rb = rep.based_on || {};
      var n = rb.attestations || 0;
      repText = "Rating: " + rep.rating
        + " (NPC agent rating rule v" + rep.rule_version
        + "; based on " + n + " attestation" + (n === 1 ? "" : "s")
        + ", " + (rb.revocations || 0) + " revoked).";
    } else if (rep && typeof rep === "object") {
      repText = "No reputation score yet. Standing on this record: "
        + kyaText(rep.based_on || {});
    } else {
      repText = kyaText(rep);
    }
    [["Principal", kyaText(kya.principal)],
     ["Permissions", kyaText(kya.permissions)],
     ["Constraints", kyaText(kya.constraints)],
     ["Reputation", repText]].forEach(function (pair) {
      dl.appendChild(el("dt", pair[0]));
      dl.appendChild(el("dd", pair[1]));
    });
    frag.appendChild(dl);
    return frag;
  }
  function showResult(rec) {
    resultBox.innerHTML = "";
    resultBox.appendChild(el("h3", "Registered."));
    var dl = document.createElement("dl");
    dl.className = "kv";
    function row(k, v, mono) {
      if (!v) return;
      dl.appendChild(el("dt", k));
      var dd = el("dd", v);
      if (mono) dd.className = "mono";
      dl.appendChild(dd);
    }
    row("Your NPC ID", rec.record_id, true);
    row("Status", "Registered, checks pending");
    row("What", rec.title || rec.agent_name || "");
    row("Registered", rec.registered_at || "");
    resultBox.appendChild(dl);
    resultBox.appendChild(el("p",
      "Registration is not verification. Your record is signed by " +
      "NPC, and anyone can look it up by its ID."));
    if (rec.record_id) resultBox.appendChild(keepBlock(rec));
    var ran = checkList("Checks that ran", rec.checks_run, "detail");
    if (ran) resultBox.appendChild(ran);
    var pending = checkList("Checks that have not run yet",
                            rec.checks_not_run, "reason");
    if (pending) resultBox.appendChild(pending);
    var kya = kyaBlock(rec.kya);
    if (kya) resultBox.appendChild(kya);
    if (window.npcRequestVerificationBox && rec.record_id) {
      resultBox.appendChild(
        window.npcRequestVerificationBox(rec.record_id, base));
    }
    var link = el("a", "See this record in Search");
    link.href = "/search?id=" + encodeURIComponent(rec.record_id);
    var p = el("p");
    p.appendChild(link);
    resultBox.appendChild(p);
    resultBox.hidden = false;
    resultBox.scrollIntoView();
  }
  function submit(path, payload) {
    if (errorBox) errorBox.hidden = true;
    if (resultBox) resultBox.hidden = true;
    fetch(base + path, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(payload)
    }).then(function (r) {
      return r.json().then(function (body) {
        return {ok: r.ok, status: r.status, body: body};
      });
    }).then(function (res) {
      if (res.ok && res.body && res.body.record_id) {
        showResult(res.body);
      } else if (res.status === 429) {
        showError("Too many registrations from this email or " +
          "address for now. Please wait, then try again.");
      } else if (res.body && res.body.detail) {
        showError(res.body.detail);
      } else {
        showError("That registration did not go through, and " +
          "nothing was registered. Please try again.");
      }
    }).catch(function () {
      setDown();
      showError("The verification service is not answering yet. " +
        "Your registration was not sent.");
    });
  }
  function wire(form, path, fields, optional) {
    if (!form) return;
    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      var payload = {};
      fields.forEach(function (name) {
        var input = form.elements[name];
        var value = input ? input.value.trim() : "";
        if (value || optional.indexOf(name) === -1) payload[name] = value;
      });
      submit(path, payload);
    });
  }
  wire(forms[0], "/v1/register/content",
       ["title", "kind", "locator", "creator_name", "creator_email"], []);
  wire(forms[1], "/v1/register/agent",
       ["agent_name", "owner_name", "owner_email", "homepage",
        "description"], ["homepage", "description"]);
  var ctrl = ("AbortController" in window) ? new AbortController() : null;
  var timer = ctrl ? setTimeout(function () { ctrl.abort(); }, 6000) : null;
  fetch(base + "/v1/health", ctrl ? {signal: ctrl.signal} : {})
    .then(function (r) {
      if (timer) clearTimeout(timer);
      if (!r.ok) { setDown(); return; }
      if (statusLine) statusLine.textContent =
        "Registration is open. Your record is issued on the spot.";
    }).catch(function () {
      if (timer) clearTimeout(timer);
      setDown();
    });
})();
"""

# Live Search lookup. Runs only on a page that carries the marker
# element (the Unknown answer, baked or rendered). While it asks
# the verification API for the ID, the page shows a neutral
# "Looking up this ID…" state in place of the Unknown answer, so a
# real record is never declared unknown before the answer arrives.
# A found registration replaces the interim state with the record,
# rendered with its proof: the signature, the signing key, the
# kind, and the checks that ran and have not run yet. A miss or an
# unreachable API restores the honest Unknown exactly as it stands.
LIVE_LOOKUP_JS = """
(function () {
  var marker = document.getElementById("npc-live-lookup");
  if (!marker || !window.fetch) return;
  var base = (marker.getAttribute("data-api-base") || "").replace(/\\/+$/, "");
  var id = marker.getAttribute("data-id") || "";
  if (!id) {
    var m = /[?&]id=([^&]+)/.exec(window.location.search || "");
    if (m) {
      try { id = decodeURIComponent(m[1]); } catch (e) { id = m[1]; }
    }
  }
  if (!base || !id) return;
  function el(tag, text) {
    var n = document.createElement(tag);
    if (text) n.textContent = text;
    return n;
  }
  function checkList(title, entries, field) {
    if (!entries || !entries.length) return null;
    var frag = document.createDocumentFragment();
    frag.appendChild(el("h3", title));
    var ul = document.createElement("ul");
    ul.className = "checklist";
    entries.forEach(function (c) {
      var li = el("li");
      var name = (c.check || "").replace(/_/g, " ");
      var detail = c[field] || c.reason || "";
      var v = c.validation;
      if (v && typeof v === "object") {
        var bits = ["Validation: " +
          String(v.status || "").replace(/_/g, " ") + "."];
        if (v.signer_subject) {
          bits.push("Signer as presented: " + v.signer_subject + ".");
        }
        detail = detail ? detail + " " + bits.join(" ")
                        : bits.join(" ");
      }
      if (!detail && c.status) {
        detail = String(c.status).replace(/_/g, " ");
      }
      var strong = el("strong", name);
      li.appendChild(strong);
      if (detail) li.appendChild(document.createTextNode(": " + detail));
      ul.appendChild(li);
    });
    frag.appendChild(ul);
    return frag;
  }
  function kyaText(v) {
    if (v === null || v === undefined) return "Not on this record.";
    if (Array.isArray(v)) return v.map(kyaText).join(", ");
    if (typeof v === "object") {
      return Object.keys(v).sort().filter(function (k) {
        return k !== "detail";
      }).map(function (k) {
        return k.replace(/_/g, " ") + ": " + kyaText(v[k]);
      }).join("; ");
    }
    return String(v);
  }
  function kyaBlock(kya) {
    if (!kya || typeof kya !== "object") return null;
    var frag = document.createDocumentFragment();
    frag.appendChild(el("h3", "Know Your Agent"));
    var dl = document.createElement("dl");
    dl.className = "kv";
    var rep = kya.reputation;
    var repText;
    if (rep && typeof rep === "object" && rep.state === "rated") {
      var rb = rep.based_on || {};
      var n = rb.attestations || 0;
      repText = "Rating: " + rep.rating
        + " (NPC agent rating rule v" + rep.rule_version
        + "; based on " + n + " attestation" + (n === 1 ? "" : "s")
        + ", " + (rb.revocations || 0) + " revoked).";
    } else if (rep && typeof rep === "object") {
      repText = "No reputation score yet. Standing on this record: "
        + kyaText(rep.based_on || {});
    } else {
      repText = kyaText(rep);
    }
    [["Principal", kyaText(kya.principal)],
     ["Permissions", kyaText(kya.permissions)],
     ["Constraints", kyaText(kya.constraints)],
     ["Reputation", repText]].forEach(function (pair) {
      dl.appendChild(el("dt", pair[0]));
      dl.appendChild(el("dd", pair[1]));
    });
    frag.appendChild(dl);
    return frag;
  }
  var notice = document.getElementById("npc-unknown-notice");
  var head = document.getElementById("npc-unknown-head");
  var pending = document.getElementById("npc-lookup-pending");
  function showPending() {
    if (head) head.hidden = true;
    if (notice) notice.hidden = true;
    if (pending) pending.hidden = false;
  }
  function showUnknown() {
    if (head) head.hidden = false;
    if (notice) notice.hidden = false;
    if (pending) pending.hidden = true;
  }
  showPending();
  fetch(base + "/v1/records/" + encodeURIComponent(id))
    .then(function (r) { return r.ok ? r.json() : null; })
    .then(function (rec) {
      if (!rec || !rec.record_type) { showUnknown(); return; }
      if (rec.record_type.indexOf("npc.registry.") !== 0) {
        showUnknown();
        return;
      }
      if (pending) pending.hidden = true;
      if (notice) notice.hidden = true;
      var card = el("div");
      card.className = "card";
      card.appendChild(el("h3", rec.title || rec.agent_name || rec.record_id));
      card.appendChild(el("p",
        "This registration was issued by NPC and signed at issuance."));
      var dl = document.createElement("dl");
      dl.className = "kv";
      function row(k, v, mono) {
        if (!v) return;
        dl.appendChild(el("dt", k));
        var dd = el("dd", v);
        if (mono) dd.className = "mono";
        dl.appendChild(dd);
      }
      row("Record ID", rec.record_id, true);
      row("Status", "Registered, checks pending");
      if (rec.kind === "agent") {
        row("Agent", rec.agent_name);
        row("Owner", rec.owner_name);
        row("Homepage", rec.homepage);
        row("About", rec.description);
      } else {
        row("Kind", rec.content_kind);
        row("Creator", rec.creator_name);
        row("Locator", rec.locator, true);
      }
      row("Registered", rec.registered_at);
      row("Signed with key", rec.key_id, true);
      row("Signature", rec.signature, true);
      card.appendChild(dl);
      card.appendChild(el("p",
        "Registration is not verification. The record lists which " +
        "checks ran and which have not."));
      var ran = checkList("Checks that ran", rec.checks_run, "detail");
      if (ran) card.appendChild(ran);
      var notRan = checkList("Checks that have not run yet",
                             rec.checks_not_run, "reason");
      if (notRan) card.appendChild(notRan);
      var kya = kyaBlock(rec.kya);
      if (kya) card.appendChild(kya);
      marker.appendChild(card);
      marker.hidden = false;
      if (window.npcIdentityPanel) {
        try { window.npcIdentityPanel(id, base); } catch (e) {}
      }
      // The request-verification state rides along: the card shows
      // "Verification requested" when the registrant has asked, and
      // the ask itself when they have not. A failed state read adds
      // nothing: no affordance is shown that was not confirmed.
      fetch(base + "/v1/records/" + encodeURIComponent(id) +
            "/verification-request")
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (state) {
          if (!state) return;
          if (state.verification_requested) {
            card.appendChild(el("p",
              "Verification requested" +
              (state.requested_at ? " on " + state.requested_at : "") +
              "."));
          } else if (window.npcRequestVerificationBox) {
            card.appendChild(window.npcRequestVerificationBox(
              id, base));
          }
        })
        .catch(function () { /* the card stands as rendered */ });
    })
    .catch(function () { showUnknown(); });
})();
"""


# Request verification (cycle completion, 2026-10-15). The widget
# is a small form: the registrant types the email they registered
# with and asks NPC for step two. It appears only where a
# registration in a pending state is being shown, and only after
# the state read confirms no request exists yet. The browser talks
# to the API directly; the answers it renders are the API's own
# outcomes, in plain customer words. A mismatch never hints whether
# the record or the email was the problem beyond what the public
# record already shows.
REQUEST_VERIFY_JS = """
(function () {
  if (!window.fetch) return;
  function el(tag, text) {
    var n = document.createElement(tag);
    if (text) n.textContent = text;
    return n;
  }
  function wire(box) {
    if (!box || box.getAttribute("data-wired")) return;
    box.setAttribute("data-wired", "1");
    var base = (box.getAttribute("data-api-base") || "")
      .replace(/\\/+$/, "");
    var id = box.getAttribute("data-record-id") || "";
    var form = box.querySelector("form");
    var status = box.querySelector(".npc-request-status");
    if (!form || !base || !id) return;
    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      var email = (form.elements["email"].value || "").trim();
      if (status) status.textContent = "Sending your request.";
      fetch(base + "/v1/records/" + encodeURIComponent(id) +
            ":request-verification", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({email: email})
      }).then(function (r) {
        return r.json().then(function (body) {
          return {ok: r.ok, status: r.status, body: body};
        });
      }).then(function (res) {
        if (res.ok) {
          form.hidden = true;
          if (status) status.textContent =
            "Verification requested. Your request is with NPC, " +
            "and this record shows it from here on.";
        } else if (res.status === 404) {
          if (status) status.textContent =
            "That email does not match this registration. Use the " +
            "address you registered with.";
        } else if (res.status === 429) {
          if (status) status.textContent =
            "Too many requests for now. Please wait, then try again.";
        } else {
          if (status) status.textContent =
            "Your request did not go through. Please try again.";
        }
      }).catch(function () {
        if (status) status.textContent =
          "The verification service is not answering yet. Your " +
          "request was not sent.";
      });
    });
  }
  function buildBox(recordId, apiBase) {
    var box = el("div");
    box.className = "npc-request-verification";
    box.setAttribute("data-record-id", recordId);
    box.setAttribute("data-api-base", apiBase);
    box.appendChild(el("h3", "Request verification"));
    box.appendChild(el("p",
      "Registration puts your work on record. Verification is the " +
      "next step, where NPC runs the remaining checks. If you " +
      "registered this work, you can ask for that step here."));
    var form = el("form");
    form.className = "npc-request-form";
    var label = el("label", "The email you registered with ");
    var input = el("input");
    input.type = "email";
    input.name = "email";
    input.required = true;
    input.setAttribute("autocomplete", "email");
    label.appendChild(input);
    form.appendChild(label);
    var button = el("button", "Request verification");
    button.type = "submit";
    form.appendChild(button);
    box.appendChild(form);
    var status = el("p");
    status.className = "npc-request-status";
    status.setAttribute("role", "status");
    box.appendChild(status);
    wire(box);
    return box;
  }
  window.npcRequestVerificationBox = buildBox;
  var boxes = document.querySelectorAll(".npc-request-verification");
  for (var i = 0; i < boxes.length; i++) wire(boxes[i]);
})();
"""


# Biblo chat widget (biblo-chat-SPEC-2026-10-15.md section 2). Plain
# browser JavaScript, no dependencies, in the same pattern as the
# Verify yours script. Rules it lives by: it renders only what the
# chat endpoint actually answered (textContent throughout, so a
# reply is never markup); the thread id lives in page memory only;
# and every failure lands on a quiet line, never a broken panel. The
# widget never blocks the page: on /verify it floats clear of the
# registration forms, and its resting state disables only itself.
CHAT_JS = """
(function () {
  if (!window.fetch) return;
  var OPENING = "Hello. I am Biblo, the assistant here at NPC Labs. " +
    "Ask me about records, registering your own work or an agent, " +
    "what the checks mean, or where the plugins stand. If I do not " +
    "know, I will say so.";
  var RATE_MSG = "That is a lot of questions for now. Please try " +
    "again in a little while, or write to hello@npclabs.xyz.";
  var DOWN_MSG = "Biblo is not reachable right now. The Help page " +
    "covers most questions, and the team reads hello@npclabs.xyz.";
  function el(tag, text, cls) {
    var n = document.createElement(tag);
    if (text) n.textContent = text;
    if (cls) n.className = cls;
    return n;
  }
  function initPanel(panel) {
    var base = (panel.getAttribute("data-api-base") || "")
      .replace(/\\/+$/, "");
    var log = panel.querySelector(".npc-chat-log");
    var form = panel.querySelector(".npc-chat-form");
    var input = form.querySelector("input");
    var sendBtn = form.querySelector("button");
    var starters = panel.querySelector(".npc-chat-starters");
    var threadId = null, turn = 0, busy = false, greeted = false;
    function scroll() { log.scrollTop = log.scrollHeight; }
    function addMsg(from, text) {
      var wrap = el("div", null, "npc-chat-msg");
      wrap.appendChild(el("p", from, "from"));
      wrap.appendChild(el("p", text));
      log.appendChild(wrap);
      scroll();
      return wrap;
    }
    function greet() {
      if (greeted) return;
      greeted = true;
      addMsg("Biblo", OPENING);
    }
    function addBiblo(text, sources, myTurn, withFeedback) {
      var wrap = addMsg("Biblo", text);
      if (sources && sources.length) {
        var srcs = el("div", null, "srcs");
        srcs.appendChild(document.createTextNode("Sources: "));
        sources.forEach(function (s) {
          var a = el("a", s.title);
          a.href = s.path;
          srcs.appendChild(a);
        });
        wrap.appendChild(srcs);
      }
      if (withFeedback && threadId) {
        var fb = el("div", null, "npc-chat-fb");
        [["up", "\\uD83D\\uDC4D", "Helpful"],
         ["down", "\\uD83D\\uDC4E", "Not helpful"]].forEach(function (o) {
          var b = el("button", o[1]);
          b.type = "button";
          b.setAttribute("aria-label", o[2]);
          b.addEventListener("click", function () {
            var btns = fb.querySelectorAll("button");
            for (var i = 0; i < btns.length; i++) btns[i].disabled = true;
            fetch(base + "/v1/chat/feedback", {
              method: "POST",
              headers: {"Content-Type": "application/json"},
              body: JSON.stringify({thread_id: threadId, turn: myTurn,
                                    rating: o[0]})
            }).catch(function () { /* feedback is best-effort */ });
          });
          fb.appendChild(b);
        });
        wrap.appendChild(fb);
      }
    }
    function rest() {
      input.disabled = true;
      sendBtn.disabled = true;
      if (starters) starters.hidden = true;
    }
    function send(text) {
      text = (text || "").trim();
      if (!text || busy) return;
      greet();
      addMsg("You", text);
      turn += 1;
      var myTurn = turn;
      busy = true;
      sendBtn.disabled = true;
      var payload = {message: text, page: window.location.pathname};
      if (threadId) payload.thread_id = threadId;
      fetch(base + "/v1/chat", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify(payload)
      }).then(function (r) {
        return r.json().then(function (b) {
          return {status: r.status, body: b};
        });
      }).then(function (res) {
        busy = false;
        sendBtn.disabled = false;
        if (res.status === 429) { addMsg("Biblo", RATE_MSG); return; }
        var b = res.body || {};
        if (b.thread_id) threadId = b.thread_id;
        if (typeof b.reply === "string") {
          addBiblo(b.reply, b.sources, myTurn, b.state !== "off");
        }
        if (b.state === "off") rest();
      }).catch(function () {
        busy = false;
        sendBtn.disabled = false;
        addMsg("Biblo", DOWN_MSG);
      });
      input.value = "";
      scroll();
    }
    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      send(input.value);
    });
    if (starters) {
      var btns = starters.querySelectorAll("button");
      for (var i = 0; i < btns.length; i++) {
        btns[i].addEventListener("click", function () {
          send(this.getAttribute("data-q"));
        });
      }
    }
    greet();
  }
  var panels = document.querySelectorAll(".npc-chat-panel");
  for (var i = 0; i < panels.length; i++) initPanel(panels[i]);
  var btn = document.getElementById("npc-chat-btn");
  var panel = document.getElementById("npc-chat-float");
  if (btn && panel) {
    btn.addEventListener("click", function () {
      var opening = panel.hidden;
      panel.hidden = !opening;
      btn.setAttribute("aria-expanded", String(opening));
      if (opening) {
        var inp = panel.querySelector("input");
        if (inp) inp.focus();
      }
    });
    var close = panel.querySelector(".npc-chat-close");
    if (close) {
      close.addEventListener("click", function () {
        panel.hidden = true;
        btn.setAttribute("aria-expanded", "false");
        btn.focus();
      });
    }
  }
})();
"""

CHAT_STARTERS = (
    "How do I register my own work?",
    "What does unknown mean?",
    "Where can I use the plugins?",
)


def chat_panel_html(api_base, floating):
    """One Biblo chat panel. The floating variant rides every page;
    the inline variant is the /help Ask Biblo section."""
    starters = "".join(
        '<button type="button" data-q="%s">%s</button>'
        % (esc(q), esc(q)) for q in CHAT_STARTERS)
    close = ('<button type="button" class="npc-chat-close" '
             'aria-label="Close chat">&times;</button>'
             ) if floating else ""
    return """
<section class="npc-chat-panel %s" data-api-base="%s"%s aria-label="Ask Biblo">
<div class="npc-chat-head"><span><span class="who">Biblo</span><span class="sub">AI assistant for NPC Labs</span></span>%s</div>
<div class="npc-chat-log"></div>
<div class="npc-chat-starters">%s</div>
<div class="npc-chat-notice">Conversations may be read by the NPC team to improve these answers. Please do not share private details here.</div>
<form class="npc-chat-form"><input type="text" maxlength="1000" placeholder="Ask about records, registering, the checks, the plugins" aria-label="Your question"><button type="submit">Send</button></form>
</section>""" % (
        "floating" if floating else "inline",
        esc(api_base),
        ' id="npc-chat-float" hidden' if floating else "",
        close, starters)


def chat_widget_html(api_base):
    """The floating corner button (Biblo's approved icon art) plus
    its panel and script, appended to every page."""
    return (
        '<button type="button" class="npc-chat-btn" id="npc-chat-btn" '
        'aria-label="Ask Biblo" aria-expanded="false" '
        'aria-controls="npc-chat-float">'
        '<img src="/assets/biblo-chat-icon-112.png" alt="" width="56" '
        'height="56"></button>'
        + chat_panel_html(api_base, floating=True)
        + "<script>%s</script>" % CHAT_JS)


def live_lookup_marker(api_base, record_id=None):
    return ('<div id="npc-live-lookup" data-api-base="%s"%s hidden></div>'
            '<script>%s</script><script>%s</script>%s' % (
                esc(api_base),
                (' data-id="%s"' % esc(record_id)) if record_id else "",
                LIVE_LOOKUP_JS, REQUEST_VERIFY_JS, IDENTITY_PANEL_JS))


def request_verification_html(record_id, api_base):
    """The server-rendered Request verification widget: the same
    markup the browser script builds on live-lookup cards, wired by
    REQUEST_VERIFY_JS wherever it ships."""
    return (
        '<div class="npc-request-verification" data-record-id="%s" '
        'data-api-base="%s">'
        '<h3>Request verification</h3>'
        '<p>Registration puts your work on record. Verification is '
        'the next step, where NPC runs the remaining checks. If you '
        'registered this work, you can ask for that step here.</p>'
        '<form class="npc-request-form">'
        '<label>The email you registered with '
        '<input type="email" name="email" required '
        'autocomplete="email"></label>'
        '<button type="submit">Request verification</button></form>'
        '<p class="npc-request-status" role="status"></p></div>'
        % (esc(record_id), esc(api_base)))


def identity_panel_html(panel):
    """Render the "Identity the owner has linked" panel from the API
    panel payload (GET /v1/records/{id}/identity-panel). The labels,
    headings, and boundary line come from the API payload itself, so
    the words on the page are the words the design approved. Renders
    nothing when nothing is linked: no section, no heading, no
    claim."""
    if not isinstance(panel, dict):
        return ""
    p = panel.get("panel") or {}
    groups = p.get("groups") or []
    gone = p.get("not_current") or []
    if not groups and not gone:
        return ""
    parts = ['<div class="card">']
    parts.append("<h3>%s</h3>" % esc(p.get("heading")))
    parts.append("<p>%s</p>" % esc(p.get("intro")))
    for group in groups:
        parts.append("<h4>%s</h4><ul>" % esc(group.get("heading")))
        for signal in group.get("signals") or []:
            parts.append("<li>%s</li>" % esc(signal.get("label")))
        parts.append("</ul>")
    if gone:
        parts.append("<h4>No longer confirmed</h4><ul>")
        for signal in gone:
            parts.append("<li>%s %s</li>" % (
                esc(signal.get("label")), esc(signal.get("reason"))))
        parts.append("</ul>")
        if p.get("not_current_note"):
            parts.append("<p>%s</p>" % esc(p.get("not_current_note")))
    parts.append('<p class="small">%s</p>' % esc(p.get("boundary")))
    parts.append("</div>")
    return "".join(parts)


# The live panel loader. Fetches the panel endpoint for a record and
# fills any .npc-identity-panel container for it (server-rendered
# record pages carry the container; the lookup flow gets one
# appended). Behind the API's NPC_IDENTITY_SIGNALS flag like the
# rest of the linking surface: with the flag off the endpoint
# answers 503 and the panel simply never appears, and a record with
# nothing linked renders no section at all.
IDENTITY_PANEL_JS = """
<script>
window.npcIdentityPanel = function (recordId, base) {
  var host = document.querySelector(
    '.npc-identity-panel[data-record-id="' + recordId + '"]');
  if (!host) {
    var result = document.getElementById('live-lookup-result')
      || document.getElementById('npc-live-lookup');
    if (!result) { return; }
    host = document.createElement('div');
    host.className = 'npc-identity-panel';
    host.setAttribute('data-record-id', recordId);
    result.appendChild(host);
  }
  if (host.getAttribute('data-loaded')) { return; }
  host.setAttribute('data-loaded', '1');
  fetch(base + '/v1/records/' + encodeURIComponent(recordId)
        + '/identity-panel')
    .then(function (r) { return r.ok ? r.json() : null; })
    .then(function (doc) {
      if (!doc || !doc.panel) { return; }
      var p = doc.panel;
      var hasCurrent = p.groups && p.groups.length;
      var hasGone = p.not_current && p.not_current.length;
      if (!hasCurrent && !hasGone) { return; }
      function esc(s) {
        return String(s == null ? '' : s).replace(/[&<>"']/g,
          function (c) {
            return {'&': '&amp;', '<': '&lt;', '>': '&gt;',
                    '"': '&quot;', "'": '&#39;'}[c];
          });
      }
      var h = '<div class="card"><h3>' + esc(p.heading) + '</h3>'
        + '<p>' + esc(p.intro) + '</p>';
      (p.groups || []).forEach(function (g) {
        h += '<h4>' + esc(g.heading) + '</h4><ul>';
        (g.signals || []).forEach(function (s) {
          h += '<li>' + esc(s.label) + '</li>';
        });
        h += '</ul>';
      });
      if (hasGone) {
        h += '<h4>No longer confirmed</h4><ul>';
        p.not_current.forEach(function (s) {
          h += '<li>' + esc(s.label) + ' ' + esc(s.reason)
            + '</li>';
        });
        h += '</ul>';
        if (p.not_current_note) {
          h += '<p>' + esc(p.not_current_note) + '</p>';
        }
      }
      h += '<p class="small">' + esc(p.boundary) + '</p></div>';
      host.innerHTML = h;
    })
    .catch(function () {});
};
document.addEventListener('DOMContentLoaded', function () {
  var nodes = document.querySelectorAll(
    '.npc-identity-panel[data-record-id]');
  for (var i = 0; i < nodes.length; i++) {
    var base = nodes[i].getAttribute('data-api-base');
    if (base) {
      window.npcIdentityPanel(
        nodes[i].getAttribute('data-record-id'), base);
    }
  }
});
</script>
"""


# -- Social connections (social profiles lane, phase 1.5) --------------
# The read-only view of the social profiles lane, on the identity
# panel pattern: the API builds an overview payload per connection
# and this module renders it (social_connection_html server-side,
# SOCIAL_CONNECTIONS_JS in the browser). The view ships only while
# the lane is enabled on this deployment, gated by the same flag
# the API gates on: with NPC_SOCIAL_PROFILES off there is no nav
# entry, no page, and no script, and every dashboard page renders
# exactly as before.

SOCIAL_PROFILES_ENV = "NPC_SOCIAL_PROFILES"

_SOCIAL_PLATFORM_DISPLAY = {
    "youtube": "YouTube",
    "instagram": "Instagram",
    "tiktok": "TikTok",
}


def social_enabled():
    return os.environ.get(SOCIAL_PROFILES_ENV) == "1"


def _social_counts_text(counts):
    counts = counts or {}
    return ("%d registered, %d new versions, %d unchanged, "
            "%d failed, %d deferred" % (
                int(counts.get("registered") or 0),
                int(counts.get("new_version") or 0),
                int(counts.get("unchanged") or 0),
                int(counts.get("failed") or 0),
                int(counts.get("deferred") or 0)))


def social_connection_html(overview):
    """Render one connection's overview payload (POST
    /v1/social/connections/{id}/overview): the platform, the
    account as the platform names it, the connection's state, its
    last scan, and what its registration batches did, each batch
    named by its receipt's record ID. The provenance sentence
    prints exactly as the payload carries it, which is exactly
    how the records carry it. Display only: a connection shows
    account control on a platform and is never rendered as
    verification. Renders nothing for an empty payload."""
    if not isinstance(overview, dict):
        return ""
    conn = overview.get("connection") or {}
    if not conn.get("connection_id"):
        return ""
    platform = conn.get("platform") or ""
    display = _SOCIAL_PLATFORM_DISPLAY.get(platform, platform)
    name = conn.get("account_display_name") or ""
    parts = ['<div class="card npc-social-connection">']
    parts.append("<h3>%s</h3>" % esc(
        display + (": " + name if name else "")))
    parts.append('<dl class="kv">')
    parts.append("<dt>Account</dt><dd>"
                 '<span class="mono">%s</span></dd>'
                 % esc(conn.get("platform_account_id")))
    parts.append("<dt>State</dt><dd>%s</dd>"
                 % esc(conn.get("status")))
    parts.append("<dt>Connected</dt><dd>%s</dd>"
                 % esc(conn.get("created_at")))
    last_scan = overview.get("last_scan")
    if last_scan:
        parts.append("<dt>Last scan</dt><dd>%s, %d works</dd>" % (
            esc(last_scan.get("enumerated_at")),
            int(last_scan.get("item_count") or 0)))
    else:
        parts.append("<dt>Last scan</dt><dd>No scan yet</dd>")
    parts.append("</dl>")
    batches = overview.get("batches") or []
    if batches:
        parts.append("<h4>Registration batches</h4><ul>")
        for batch in batches:
            parts.append(
                '<li><span class="mono">%s</span> %s: %s</li>' % (
                    esc(batch.get("batch_id")),
                    esc(batch.get("registered_at")),
                    esc(_social_counts_text(batch.get("counts")))))
        parts.append("</ul>")
        if len(batches) > 1:
            parts.append("<p>In total: %s.</p>" % esc(
                _social_counts_text(overview.get("totals"))))
    else:
        parts.append(
            "<p>No registrations yet from this connection.</p>")
    if overview.get("provenance"):
        parts.append('<p class="small">%s</p>'
                     % esc(overview.get("provenance")))
    parts.append("</div>")
    return "".join(parts)


def social_connections_html(overviews):
    """Every connection card for one owner, or nothing at all."""
    if not overviews:
        return ""
    return "".join(social_connection_html(o) for o in overviews)


# The browser half of the view. The visitor enters the email they
# connected with; the script asks the API for that owner's
# connections and then each connection's overview, and builds the
# same cards social_connection_html builds. It offers no write
# action: if the API does not answer, or the lane is off, the page
# says so plainly and shows nothing it cannot back.
SOCIAL_CONNECTIONS_JS = """
(function () {
  var root = document.getElementById('npc-social');
  if (!root || !window.fetch) { return; }
  var base = (root.getAttribute('data-api-base') || '')
    .replace(/\\/+$/, '');
  var form = document.getElementById('npc-social-form');
  var status = document.getElementById('npc-social-status');
  var results = document.getElementById('npc-social-results');
  var DISPLAY = {youtube: 'YouTube', instagram: 'Instagram',
                 tiktok: 'TikTok'};
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g,
      function (c) {
        return {'&': '&amp;', '<': '&lt;', '>': '&gt;',
                '"': '&quot;', "'": '&#39;'}[c];
      });
  }
  function countsText(c) {
    c = c || {};
    function n(k) { return parseInt(c[k] || 0, 10) || 0; }
    return n('registered') + ' registered, ' + n('new_version')
      + ' new versions, ' + n('unchanged') + ' unchanged, '
      + n('failed') + ' failed, ' + n('deferred') + ' deferred';
  }
  function card(o) {
    if (!o || !o.connection || !o.connection.connection_id) {
      return '';
    }
    var conn = o.connection;
    var display = DISPLAY[conn.platform] || conn.platform || '';
    var name = conn.account_display_name || '';
    var h = '<div class="card npc-social-connection"><h3>'
      + esc(display + (name ? ': ' + name : '')) + '</h3>'
      + '<dl class="kv">'
      + '<dt>Account</dt><dd><span class="mono">'
      + esc(conn.platform_account_id) + '</span></dd>'
      + '<dt>State</dt><dd>' + esc(conn.status) + '</dd>'
      + '<dt>Connected</dt><dd>' + esc(conn.created_at) + '</dd>';
    if (o.last_scan) {
      h += '<dt>Last scan</dt><dd>'
        + esc(o.last_scan.enumerated_at) + ', '
        + (parseInt(o.last_scan.item_count || 0, 10) || 0)
        + ' works</dd>';
    } else {
      h += '<dt>Last scan</dt><dd>No scan yet</dd>';
    }
    h += '</dl>';
    var batches = o.batches || [];
    if (batches.length) {
      h += '<h4>Registration batches</h4><ul>';
      batches.forEach(function (b) {
        h += '<li><span class="mono">' + esc(b.batch_id)
          + '</span> ' + esc(b.registered_at) + ': '
          + esc(countsText(b.counts)) + '</li>';
      });
      h += '</ul>';
      if (batches.length > 1) {
        h += '<p>In total: ' + esc(countsText(o.totals))
          + '.</p>';
      }
    } else {
      h += '<p>No registrations yet from this connection.</p>';
    }
    if (o.provenance) {
      h += '<p class="small">' + esc(o.provenance) + '</p>';
    }
    return h + '</div>';
  }
  function post(path, email) {
    return fetch(base + path, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({email: email})
    }).then(function (r) { return r.ok ? r.json() : null; });
  }
  form.addEventListener('submit', function (ev) {
    ev.preventDefault();
    var email = document.getElementById('npc-social-email').value;
    results.innerHTML = '';
    status.textContent = 'Loading your connections...';
    post('/v1/social/connections/list', email)
      .then(function (doc) {
        if (!doc || !doc.connections) {
          status.textContent = 'Your connections could not be '
            + 'loaded. The service may be unavailable; try again '
            + 'shortly.';
          return;
        }
        if (!doc.connections.length) {
          status.textContent = 'No connections found for that '
            + 'email.';
          return;
        }
        status.textContent = '';
        doc.connections.forEach(function (conn) {
          post('/v1/social/connections/'
               + encodeURIComponent(conn.connection_id)
               + '/overview', email)
            .then(function (overview) {
              var h = card(overview);
              if (h) { results.innerHTML += h; }
            })
            .catch(function () {});
        });
      })
      .catch(function () {
        status.textContent = 'Your connections could not be '
          + 'loaded. The service may be unavailable; try again '
          + 'shortly.';
      });
  });
})();
"""


def social_view(api_base=PUBLIC_API_BASE):
    """Your social connections: the lane's read-only view. The
    visitor enters the email they connected with and sees their
    connections, each one's last scan, and its registration
    outcomes. This page exists only while the lane is enabled
    (see social_enabled); it carries no write action."""
    return """
<h1>Social connections</h1>
<p class="lede">The accounts you have connected to Verified by NPC, what the last scan of each one held, and what came of its registrations.</p>
<p>Connecting an account shows control of that account on its platform. Registration is the start of verification, not the result.</p>
<div id="npc-social" data-api-base="%s">
<form class="npc-social-form" id="npc-social-form">
<label>The email you connected with
<input type="email" id="npc-social-email" required autocomplete="email"></label>
<button type="submit">Show my connections</button></form>
<p class="npc-social-status" role="status"></p>
<div id="npc-social-results"></div>
</div>
<script>%s</script>""" % (esc(api_base), SOCIAL_CONNECTIONS_JS)


def page(title, body, api_url):
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%s - Verified by NPC</title>
<style>%s</style>
</head>
<body>
<header class="top"><div class="wrap top-in">
<a class="brand" href="/">Verified by NPC</a>
<nav>
<a href="/records">Records</a><a href="/search">Search</a><a href="/plugins">Plugins</a><a href="/api">API</a><a href="/verify">Verify yours</a><a href="/help">How it works</a>%s
</nav>
</div></header>
<main class="wrap">
%s
</main>
<footer class="foot wrap">
<span>Internal preview. Local only. <a href="/privacy">Privacy</a></span>
<span>Reading from %s</span>
</footer>
%s
</body>
</html>""" % (esc(title), CSS,
              '<a href="/social">Social</a>' if social_enabled()
              else "",
              body, esc(api_url),
              chat_widget_html(api_url) if CHAT_WIDGET_ENABLED else "")


def _pill(cls, label):
    return '<span class="pill%s">%s</span>' % (
        (" " + cls) if cls else "", esc(label))


def verdict_pill(verdict, status=None):
    """Text status label from API verdict/status words. Data, not the mark."""
    v = (verdict or "").lower()
    s = (status or "").lower()
    if s == "valid":
        return _pill("verified", "Valid")
    if s == "authentic":
        return _pill("verified", "Authentic")
    if v == "verified":
        return _pill("verified", "Verified")
    if v == "verified_with_caveats":
        return _pill("caveats", "Verified with caveats")
    if s == "revoked":
        return _pill("bad", "Revoked")
    if s == "expired":
        return _pill("bad", "Expired")
    if s == "counterfeit":
        return _pill("bad", "Counterfeit")
    if v == "not_verified":
        return _pill("bad", "Not verified")
    return _pill("", "Unknown")


def scope_chips(scope):
    if not isinstance(scope, dict) or not scope:
        return '<span class="dim">No scope recorded.</span>'
    out = ['<div class="scope">']
    for key in sorted(scope):
        val = scope[key]
        if isinstance(val, list):
            val = ", ".join(str(v) for v in val)
        out.append('<span>%s: %s</span>' % (esc(key), esc(val)))
    out.append('</div>')
    return "".join(out)


def _kya_value_text(value):
    """One KYA field value as plain display text."""
    if value is None:
        return "Not on this record."
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return ", ".join(_kya_value_text(v) for v in value)
    if isinstance(value, dict):
        bits = []
        for key in sorted(value):
            if key == "identity_signals" \
                    and isinstance(value[key], list):
                providers = ", ".join(
                    str(s.get("provider", "")) for s in value[key]
                    if isinstance(s, dict))
                bits.append("linked identity checks: %s" % providers)
            elif key == "detail":
                continue
            else:
                bits.append("%s: %s" % (
                    str(key).replace("_", " "),
                    _kya_value_text(value[key])))
        return "; ".join(bits) if bits else "Not on this record."
    return str(value)


def kya_html(rec):
    """Render a record's KYA block (Know Your Agent), when it has one.

    The API adds the block to agent records only while
    NPC_KYA_FIELDS=1, so a record without the block renders exactly
    as before: this returns an empty string and no section appears.
    Display only: every value prints as the record carries it, and
    a field the record does not carry prints as not on this record.
    A reputation entry that carries the agent's rating prints the
    rating with its rule version and basis counts; a standing
    facts entry with no rating prints that plainly rather than
    inventing one.
    """
    if not isinstance(rec, dict):
        return ""
    kya = rec.get("kya")
    if not isinstance(kya, dict):
        return ""
    reputation = kya.get("reputation")
    if isinstance(reputation, dict) \
            and reputation.get("state") == "rated":
        basis = reputation.get("based_on") or {}
        count = basis.get("attestations") or 0
        reputation_text = (
            "Rating: %s (NPC agent rating rule v%s; based on "
            "%s attestation%s, %s revoked)."
            % (reputation.get("rating"),
               reputation.get("rule_version"), count,
               "" if count == 1 else "s",
               basis.get("revocations") or 0))
    elif isinstance(reputation, dict):
        basis = reputation.get("based_on") or {}
        reputation_text = (
            "No reputation score yet. Standing on this record: %s."
            % _kya_value_text(basis)) if basis else \
            "No reputation score yet."
    else:
        reputation_text = _kya_value_text(reputation)
    rows = [
        ("Principal", _kya_value_text(kya.get("principal"))),
        ("Permissions", _kya_value_text(kya.get("permissions"))),
        ("Constraints", _kya_value_text(kya.get("constraints"))),
        ("Reputation", reputation_text),
    ]
    items = "".join(
        "<dt>%s</dt><dd>%s</dd>" % (esc(name), esc(text))
        for name, text in rows)
    return ('<h3>Know Your Agent</h3>'
            '<dl class="kv">%s</dl>'
            "<p class=\"small\">These fields name who this agent "
            "acts for, what it may do, the bounds on that, and its "
            "standing, so a reader can check them without guessing."
            "</p>" % items)


def registration_invitation():
    """The Unknown answer's invitation, shared by both unknown surfaces.

    Unknown still means no record; this only tells the owner of the
    work or agent how to put it on record."""
    return ('<p>If this work or this agent is yours, you can '
            '<a href="/verify">put it on record</a> in about a minute. '
            'Registration is free, and your record starts as registered, '
            'checks pending.</p>')


def unknown_notice(subject, notice_id=None):
    id_attr = (' id="%s"' % esc(notice_id)) if notice_id else ""
    return ('<div class="notice"%s><h3>Unknown</h3>'
            '<p>We have no record of %s. That means unknown, not false. '
            'We never guess.</p>%s</div>' % (
                id_attr, esc(subject), registration_invitation()))


def unavailable_notice(detail=""):
    msg = ("<p>The verification service could not be reached or its answer "
           "could not be confirmed. Nothing is shown rather than something "
           "unverified.</p>")
    if detail:
        msg += "<p class=\"mono\">%s</p>" % esc(detail)
    return '<div class="notice"><h3>Unavailable</h3>%s</div>' % msg


# -- pages --------------------------------------------------------------


def home_view():
    return """
<p class="kicker">NPC Labs</p>
<h1>Know what is real before you act on it.</h1>
<p class="lede">Verified by NPC is a trust layer for the things you buy, earn, and build with. Products, credentials, claims, and agents, each checked against signed records you can confirm yourself.</p>

<h2>Why it exists</h2>
<p>People are asked to trust more than ever: a product listing, a certificate, a claim in a pitch, an agent asking for access. Trust should rest on something you can check, not on a logo or a promise. Every answer here is signed by NPC, and the public keys behind those signatures are published in Search. If we do not know, we say unknown.</p>

<div class="row">
<div class="card"><h3><a href="/records">Records</a></h3>
<p>See what has actually been tested, and what the findings were.</p></div>
<div class="card"><h3><a href="/search">Search</a></h3>
<p>Look up digital and physical IDs in one place: credentials, products, archive items, and public keys.</p></div>
<div class="card"><h3><a href="/plugins">Plugins</a></h3>
<p>See where each assistant integration stands, and what it will answer.</p></div>
<div class="card"><h3><a href="/verify">Verify yours</a></h3>
<p>Start verification of your own work: register a piece of work, or an agent you run.</p></div>
<div class="card"><h3><a href="/help">How it works</a></h3>
<p>A guide to the record, the search, and how to read an answer.</p></div>
</div>

<h2>How it reaches you</h2>
<p>The plugins carry these answers into the assistants people already use. Three are live today; the <a href="/plugins">Plugins page</a> shows the current status of each one.</p>

<h2>Put your own work on record.</h2>
<p>Looking something up is one half of this. The other half is yours: if you make work, sell a product, or run an agent, you can put it on record and start its verification.</p>
<ol class="steps">
<li><strong>Register your work or your agent.</strong> A title, its kind, and where it can be found is what it takes to start.</li>
<li><strong>Get a signed record with its own NPC ID, on the spot.</strong> From that moment, anyone can look it up in Search by its ID.</li>
<li><strong>Your checks run, and the record updates as they complete.</strong> What has run, and what is still pending, is written in the record itself.</li>
</ol>
<p>Registration is free, and it takes about a minute.</p>
<p><a href="/verify" style="display:inline-block;background:#ec662b;color:#fff;padding:11px 20px;border-radius:10px;font-weight:600;text-decoration:none">Verify yours</a></p>

<h2>First to know.</h2>
<p>The NPC Verify extension, the Verified Agent Library, the Verified Agent Builder, and new releases land here first. Join the list.</p>
<form class="lookup" name="waitlist" method="POST" data-netlify="true">
<input type="hidden" name="form-name" value="waitlist">
<input type="email" name="email" required aria-label="Email address" style="flex:1;min-width:200px;padding:11px 14px;font-size:15px;border:1px solid var(--line);border-radius:10px;background:var(--card);color:var(--ink)">
<button type="submit" style="background:#ec662b">Join the waitlist</button>
</form>
<p class="examples">The public API is live, and live checking is open. The records shown here are samples. The NPC Verify extension is still to come; the waitlist is the way to hear when it lands.</p>

<p class="examples">Everything shown is a sample record. Nothing here is a real product, credential, or person.</p>
"""


def plugins_view():
    return """
<p class="kicker">Distribution</p>
<h1>NPC checks, inside the assistants you use.</h1>
<p class="lede">The plugins let you ask for an NPC check inside an assistant and follow the answer back to the signed record. Three are live today. Each one below shows where it stands.</p>

<h2>What a plugin will answer</h2>
<div class="card"><h3>Is this product authentic?</h3><p>Smart-tag lookup, with provenance.</p></div>
<div class="card"><h3>Is this certificate real?</h3><p>Credential lookup, with status and revocation.</p></div>
<div class="card"><h3>Did this really happen?</h3><p>Claim matched against attested records, findings included.</p></div>
<div class="card"><h3>Is this agent verified?</h3><p>Agent attestation: verdict, scope, and time bounds.</p></div>
<div class="card"><h3>What does Verified by NPC mean?</h3><p>What a verified answer means, and what it does not.</p></div>

<h2>Where each one stands</h2>
<table>
<tr><th>Assistant</th><th>Surface</th><th>Status</th></tr>
<tr><td>Claude</td><td class="dim">MCP server for MCP clients</td><td>Live. The MCP server is published on PyPI as npc-verify-mcp, and a hosted endpoint answers too, so MCP clients can ask today.</td></tr>
<tr><td>ChatGPT</td><td class="dim">Plugin / GPT action</td><td>Live. Verified by NPC is published in ChatGPT, and its five tools answer there. <a href="https://chatgpt.com/plugins/plugin_asdk_app_6ad08902b430819197e94c02b474b440">Open the listing</a>.</td></tr>
<tr><td>Gemini</td><td class="dim">Extension</td><td>Live. The Gemini extension, version 1.0.2, is published on GitHub. <a href="https://github.com/bayo-de/npc-verify-gemini">Get it on GitHub</a>.</td></tr>
<tr><td>Copilot</td><td class="dim">Plugin</td><td>In enrollment with Microsoft. Submission follows when enrollment completes.</td></tr>
</table>

<h2>The public API is live</h2>
<p>Every live integration above answers through the public API at api.npclabs.xyz, against live records, with the full answer waiting on the record itself. Copilot joins them once its enrollment with Microsoft completes.</p>
<p>The NPC Verify extension for Chrome is coming soon. For news on it and on Copilot, <a href="/">join the waitlist on the home page</a>.</p>
"""


def _codebox(text):
    """A preformatted example block in the site's quiet box styling."""
    return ('<div class="keybox mono" style="white-space:pre;'
            'overflow-x:auto;line-height:1.55">%s</div>' % esc(text))


_HEALTH_CALL = """curl https://api.npclabs.xyz/v1/health"""

_HEALTH_RESPONSE = """{
  "chain": {
    "anchoring": "disabled",
    "mode": "local-first",
    "network": "none",
    "note": "Phase 1 records anchor hashes locally; no chain writes until the mainnet gate clears."
  },
  "key_id": "npc-demo-api-signing-20261014-e9c73a",
  "status": "ok",
  "time": "2026-10-16T02:35:14+00:00",
  "version": "1.0.0"
}"""

_AGENT_REQUEST = """curl -X POST https://api.npclabs.xyz/v1/register/agent \\
  -H "Content-Type: application/json" \\
  -H "Idempotency-Key: api-docs-example-2026-10-15" \\
  -d '{
    "agent_name": "Docs Example Agent",
    "owner_name": "NPC Labs",
    "owner_email": "hello@npclabs.xyz",
    "description": "An example agent registered to document the Verified by NPC API."
  }'"""

_AGENT_RESPONSE = """{
  "record_id": "reg_6789fb4ca0f5363853a23dc0",
  "record_type": "npc.registry.agent_registration",
  "kind": "agent",
  "agent_name": "Docs Example Agent",
  "owner_name": "NPC Labs",
  "description": "An example agent registered to document the Verified by NPC API.",
  "homepage": null,
  "status": "registered_checks_pending",
  "status_label": "registered, checks pending",
  "registered_at": "2026-10-16T02:35:35+00:00",
  "checks_run": [
    {
      "check": "named_owner",
      "status": "recorded",
      "detail": "The registration names an accountable owner, as the registry requires. NPC records the owner; it does not operate the agent."
    },
    {
      "check": "registration_claim",
      "status": "issued",
      "detail": "This signed claim records the registration of the agent. Registration is not verification."
    }
  ],
  "checks_not_run": [
    {
      "check": "scope_review",
      "reason": "The agent's declared scope of authority has not been reviewed yet."
    },
    {
      "check": "human_review",
      "reason": "A person has not reviewed this registration yet."
    },
    {
      "check": "verification_decision",
      "reason": "Registration is not verification. No verification decision has been made, and no verification mark is issued at registration."
    }
  ],
  "key_id": "npc-demo-issuer-20261014-727fb5",
  "signature": "/gfFVDAqu3QufnzSM/K3RaMARDFysuAc4NiyYjAaVhfugGI1KryI7y03UroMjePTZuDLucmNRDsJnAw4rUAMBQ=="
}"""

_CONTENT_REQUEST = """curl -X POST https://api.npclabs.xyz/v1/register/content \\
  -H "Content-Type: application/json" \\
  -d '{
    "title": "API documentation example text",
    "kind": "text",
    "locator": "sha256:6f64362c5920bee25236a3bd0783160665cf0b3c370946b5bbd20e94d2862da3",
    "creator_name": "NPC Labs",
    "creator_email": "hello@npclabs.xyz"
  }'"""

_CONTENT_RESPONSE = """{
  "record_id": "reg_d8b68b02eb095431acc031d2",
  "record_type": "npc.registry.content_registration",
  "kind": "content",
  "content_kind": "text",
  "title": "API documentation example text",
  "locator": "sha256:6f64362c5920bee25236a3bd0783160665cf0b3c370946b5bbd20e94d2862da3",
  "locator_kind": "content_hash",
  "creator_name": "NPC Labs",
  "status": "registered_checks_pending",
  "status_label": "registered, checks pending",
  "registered_at": "2026-10-16T02:35:41+00:00",
  "checks_run": [
    {
      "check": "content_hash",
      "status": "provided_by_creator",
      "detail": "The creator provided this content hash. NPC has not seen the content itself.",
      "locator": "sha256:6f64362c5920bee25236a3bd0783160665cf0b3c370946b5bbd20e94d2862da3"
    }
  ],
  "checks_not_run": [
    {
      "check": "human_review",
      "reason": "A person has not reviewed this registration yet."
    },
    {
      "check": "verification_decision",
      "reason": "Registration is not verification. No verification decision has been made, and no verification mark is issued at registration."
    }
  ],
  "key_id": "npc-demo-issuer-20261014-727fb5",
  "signature": "AfnTGvaj84XJSTvRoy9RHlkRVEF6lMtatt3gwU+0B67kfpuRKtlcDVdtcRNOecqau/1B+RG6jeeRSzC5cDfIAA=="
}"""

_RECORD_CALL = """curl https://api.npclabs.xyz/v1/records/reg_6789fb4ca0f5363853a23dc0"""

_UNKNOWN_CALL = """curl https://api.npclabs.xyz/v1/records/reg_000000000000000000000000

404
{"verdict": "unknown"}"""

_KEYS_CALL = """curl https://api.npclabs.xyz/v1/keys"""

_KEYS_EXCERPT = """{
  "api_signing": {
    "current": {
      "algorithm": "Ed25519",
      "key_id": "npc-demo-api-signing-20261014-e9c73a",
      "public_key": "sl7vwSgymgvrTaHg8l4FIKAPzoSYvXLH3Jm2zj/Ji/A=",
      "status": "active",
      "created_at": "2026-10-15T04:26:54+00:00",
      "retired_at": null
    }
  },
  "issuers": [
    {
      "algorithm": "Ed25519",
      "key_id": "npc-demo-issuer-20261014-727fb5",
      "public_key": "9keaHrMrvoaLX9kvl/3l7pagM91FOrlCC6EPJv1VYfA=",
      "status": "active",
      "created_at": "2026-10-15T04:26:54+00:00",
      "retired_at": null
    }
  ]
}"""

_MCP_CONFIG = """{
  "mcpServers": {
    "npc-verify": {
      "url": "https://api.npclabs.xyz/v1/mcp"
    }
  }
}"""

_MCP_TOOLS_CALL = """curl -X POST https://api.npclabs.xyz/v1/mcp \\
  -H "Content-Type: application/json" \\
  -H "Accept: application/json, text/event-stream" \\
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/list",
    "params": {}
  }'"""


def api_view():
    parts = ["""
<p class="kicker">For developers</p>
<h1>The signed record, from your own code.</h1>
<p class="lede">The Verified by NPC API is live at api.npclabs.xyz. Register the agents and content you ship, look their records up from your own application, and check NPC's signatures yourself, against keys NPC publishes. No API key is needed, and registration is free.</p>

<h2>What you can build</h2>
<div class="row">
<div class="card"><h3>Put an agent on record</h3>
<p>Register an agent you run and get a signed record with its own NPC ID, issued on the spot. The record names the agent's accountable owner and states what has been checked and what has not.</p></div>
<div class="card"><h3>Put content on record</h3>
<p>Register an image, text, audio, video, or other content, by web address or by content hash. The answer is the same kind of signed record, ready to cite wherever the content travels.</p></div>
</div>
<div class="row">
<div class="card"><h3>Look any record up</h3>
<p>One call resolves an NPC ID to its signed record: registrations, credentials, products, and agents. An ID with no record answers unknown, plainly, and never a guess.</p></div>
<div class="card"><h3>Check the signature yourself</h3>
<p>Every record is signed with Ed25519, and the public keys are published. Your code can confirm a record came from NPC and has not been changed, without calling NPC at all.</p></div>
</div>

<h2>Quickstart</h2>
<p>Every call below is real. The examples were run against the live API while this page was written, and the records they made are live records you can look up.</p>

<p><strong>1. Check the service.</strong></p>
"""]
    parts.append(_codebox(_HEALTH_CALL))
    parts.append(_codebox(_HEALTH_RESPONSE))
    parts.append("""
<p><strong>2. Register an agent.</strong> An agent registration names the agent and its accountable owner. A homepage or a description is required. The owner's email is required too, and it never appears in the public record.</p>
""")
    parts.append(_codebox(_AGENT_REQUEST))
    parts.append("<p>The answer, status 201, is the signed record, "
                 "issued on the spot:</p>")
    parts.append(_codebox(_AGENT_RESPONSE))
    parts.append("""
<p>The status says what the record is: registered, checks pending. Registration is the start of verification, not the result, and no verification mark is issued at registration. The record itself lists the checks that ran and the ones that have not.</p>

<p><strong>3. Register content.</strong> The kind is one of image, text, audio, video, or other. The locator is a web address where the content can be fetched, or its SHA-256 hash, written as sha256: followed by the hash. Content at a web address is fetched once at intake, and its SHA-256 is recorded. This example registers by hash, so the record carries the hash the creator provided:</p>
""")
    parts.append(_codebox(_CONTENT_REQUEST))
    parts.append(_codebox(_CONTENT_RESPONSE))
    parts.append("""
<p>For an image, intake also reads the image's C2PA content credentials, recording whether they are present and how they are structured, and records an AI-generation signal as a percentage with its uncertainty stated. A signal is information, not a verdict, and the record says which is which.</p>

<p><strong>4. Look a record up.</strong> The same record answers at its own address, and <a href="/search">Search</a> on this site resolves the same IDs:</p>
""")
    parts.append(_codebox(_RECORD_CALL))
    parts.append("<p>An ID with no record fails closed:</p>")
    parts.append(_codebox(_UNKNOWN_CALL))
    parts.append("""
<p><strong>5. Check the signature.</strong> Records carry their signature inside them, and every API response carries one in its headers: X-NPC-Signature, with the signing key named by X-NPC-Key-ID. The public keys live at one address:</p>
""")
    parts.append(_codebox(_KEYS_CALL))
    parts.append("<p>The current keys, from that document. Retired keys "
                 "are listed there too, marked retired, so older records "
                 "stay checkable:</p>")
    parts.append(_codebox(_KEYS_EXCERPT))
    parts.append("""
<ol class="steps">
<li><strong>Find the key.</strong> Take the record's key_id and find that entry in the keys document.</li>
<li><strong>Canonicalize.</strong> Remove the signature field, then write what is left as NPC-JCS-v1: UTF-8, keys in sorted order, no extra whitespace.</li>
<li><strong>Verify.</strong> Check the base64 Ed25519 signature against that entry's public key.</li>
</ol>
<p>The example record above passes this check, and changing any field in it makes the check fail.</p>

<h2>The MCP endpoint</h2>
<p>If you build with agents, the same records are one connection away. NPC runs a hosted MCP server at <span class="mono">https://api.npclabs.xyz/v1/mcp</span>. Point an MCP client at that address:</p>
""")
    parts.append(_codebox(_MCP_CONFIG))
    parts.append("""
<p>Its tool list answers today with seven tools. Four verify against the records (verify_claim, verify_credential, verify_product, verify_agent), one explains an answer in plain words (explain_verification), and two register from inside the conversation (register_agent, register_content):</p>
""")
    parts.append(_codebox(_MCP_TOOLS_CALL))
    parts.append("""
<p>Prefer to run the server yourself: the same tools ship on PyPI as <a href="https://pypi.org/project/npc-verify-mcp/">npc-verify-mcp</a>, version 1.0.1.</p>
""")
    parts.append(_codebox("pip install npc-verify-mcp"))
    parts.append("""
<h2>Good to know</h2>
<ul class="checklist">
<li><strong>Registration is free,</strong> and the public endpoints on this page need no API key.</li>
<li><strong>A named owner is required.</strong> An agent registration names an accountable person as its owner; anonymous owners and team aliases are not accepted.</li>
<li><strong>Emails stay private.</strong> The owner or creator email is required for registration. It stays on NPC's servers, for caps and contact, and never appears in the signed public record.</li>
<li><strong>Retries are safe.</strong> Send an Idempotency-Key header with a registration, and repeating the same request with the same key returns the original record instead of making a second one.</li>
<li><strong>Registration is capped</strong> at 10 per email address and 50 per IP address in 24 hours. Past the cap the API answers 429, and the request can be sent again later.</li>
<li><strong>Requests are capped at 1 MiB.</strong></li>
<li><strong>Records are signed, not minted.</strong> A record is an Ed25519 signature kept by NPC; registering writes nothing to a blockchain.</li>
<li><strong>Status means what it says.</strong> A new record starts as registered, checks pending. Its status changes only when its checks run, and the record lists which checks those were.</li>
</ul>

<h2>Which surface should you use?</h2>
<table>
<tr><th>Surface</th><th>Fits</th><th>Use it when</th></tr>
<tr><td>REST API</td><td class="dim">Your own application or service</td><td>You want registration and record lookups inside your own code.</td></tr>
<tr><td>Hosted MCP</td><td class="dim">Agent frameworks and MCP clients</td><td>You want an agent to ask, and to register, as it works, with no server of your own to run.</td></tr>
<tr><td>npc-verify-mcp</td><td class="dim">Your own infrastructure</td><td>You want to run the MCP server yourself, against the same live API.</td></tr>
<tr><td>Plugins</td><td class="dim">ChatGPT, Gemini, and other assistants</td><td>You want NPC checks inside an assistant your users already open. See the <a href="/plugins">Plugins page</a>.</td></tr>
</table>
<p>Questions about building on the API: <a href="mailto:hello@npclabs.xyz">hello@npclabs.xyz</a>.</p>
""")
    return "".join(parts)


def privacy_view(last_updated):
    """The NPC Verify privacy policy, rendered for the public site.

    The text is the policy draft staged with the Chrome Web Store
    submission package (extension-store-submission/PRIVACY-POLICY.md),
    verbatim apart from the filled-in date. It describes the extension
    exactly as v1.0.0 behaves; if the behavior changes, the policy
    changes first. One section is newer than the staged draft: the
    "Talking with Biblo" section below, added 2026-10-15 with the
    site chat it describes (biblo-chat spec sections 2 and 8), in
    the same change as the widget itself.
    """
    return """
<p class="kicker">NPC Verify</p>
<h1>NPC Verify Privacy Policy</h1>
<p class="lede">Last updated: %s</p>

<p>NPC Verify is a browser extension from NPC Labs. It checks whether an image on a web page is registered with NPC Labs. This policy says what the extension does with data, in plain terms.</p>

<h2>What the extension sends</h2>
<p>When you run a check, the extension computes a SHA-256 hash of the image's web address on your device and sends that hash to the NPC verification API (api.npclabs.xyz). The API answers whether a record exists for that hash.</p>
<p>The extension never sends the image itself, the image's address, the page you are on, or anything about you to NPC Labs.</p>
<p>The API's answer is cryptographically signed, and the extension verifies that signature on your device before showing you a result. NPC's API logs are operational (timestamps, request paths, response codes). The hash of an image address can, in principle, be matched against known public image addresses; it cannot be reversed into the address of an image that is not already public.</p>

<h2>What stays on your device</h2>
<p>Image forensics (reading the file's embedded metadata) happen entirely on your device. The image bytes are read into memory for the check and are never transmitted, stored, or shared.</p>
<p>The extension stores two things in your browser's local extension storage: a counter of how many free checks you have run, and, only if you or your developer set them, an API address and key override. NPC Labs cannot see either.</p>

<h2>What the extension does not do</h2>
<p>No accounts. No analytics. No advertising. No tracking across sites. No sale or sharing of data with third parties. No remote code: everything the extension runs ships inside the extension.</p>
<p>Two optional links in the results, Google Lens and TinEye, open those services in a new tab with the image address, only when you click them. Their privacy policies apply there.</p>

<h2>Talking with Biblo on this site</h2>
<p>This site offers Biblo, an AI assistant that answers questions about Verified by NPC from NPC Labs' public pages and published articles. What you type into the chat is sent to NPC's chat service so it can answer you. Conversations are kept for 90 days and may be read by the NPC team to improve these answers. Please do not share private details in the chat. The chat needs no account, and it cannot look records up or change them: Search is where a record speaks.</p>

<h2>Contact</h2>
<p>Questions about this policy: <a href="mailto:hello@npclabs.xyz">hello@npclabs.xyz</a>.</p>
""" % esc(last_updated)


def records_view(rows):
    parts = ["""
<p class="kicker">Attestation records</p>
<h1>What has been tested.</h1>
<p class="lede">Each record is a signed statement about one subject: what was checked, when, and what the findings were.</p>
<p>Looking for one thing by its ID? <a href="/search">Use Search</a>. Search covers credential, product, archive, and public key IDs in one place.</p>
"""]
    if rows:
        parts.append('<table><tr><th>Subject</th><th>Result</th><th>Scope</th>'
                     '<th>Tested</th><th>Findings</th></tr>')
        for r in rows:
            parts.append("<tr><td>%s<br><span class=\"dim mono\">%s</span></td>"
                         "<td>%s</td><td>%s</td><td class=\"dim\">%s</td>"
                         "<td>%s</td></tr>" % (
                             esc(r["label"]), esc(r["subject_id"]),
                             verdict_pill(r["verdict"]),
                             scope_chips(r["scope"]),
                             esc(r["tested_at"]),
                             esc(r["findings"])))
        parts.append("</table>")
    else:
        parts.append(unavailable_notice(
            "No records could be confirmed right now."))
    parts.append("""
<h2>Archive</h2>
<p>Real NPC Labs items, minted on chain in 2023 and 2024 and kept as company history.</p>
<p><a href="/archive">Browse the archive</a></p>
<p class="examples">Records shown are test samples.</p>""")
    return "".join(parts)


def _search_form(value=""):
    return """
<form class="lookup" method="get" action="/search">
<input type="text" name="id" placeholder="Credential, product, archive, or key ID" value="%s" aria-label="ID to look up">
<button type="submit">Search</button>
</form>
""" % esc(value)


def credential_result(cred):
    if not cred:
        return ""
    return ('<div class="card"><h3>%s</h3><p>%s</p>'
            '<dl class="kv">'
            '<dt>Status</dt><dd>%s</dd>'
            '<dt>Credential ID</dt><dd class="mono">%s</dd>'
            '<dt>Issuer</dt><dd>%s</dd>'
            '<dt>Holder</dt><dd>%s</dd>'
            '<dt>Issued</dt><dd>%s</dd>'
            '<dt>Expires</dt><dd>%s</dd>'
            '<dt>Assessed</dt><dd>%s</dd>'
            '</dl></div>' % (
                esc(cred["title"]), esc(cred["issuer"]),
                verdict_pill(None, cred["status"]),
                esc(cred["id"]), esc(cred["issuer"]),
                esc(cred["holder_name"] or "Not public"),
                esc(cred["issued_at"]),
                esc(cred["expires_at"] or "No expiry"),
                esc(", ".join(cred.get("assessed_skills", [])) or "None listed")))


def product_result(product):
    if not product:
        return ""
    prov = product.get("provenance") or []
    prov_html = "".join(
        '<li><span class="ev">%s</span><br>'
        '<span class="at">%s</span><br>'
        '<span class="dt">%s</span></li>' % (
            esc(ev.get("event")), esc(ev.get("at")),
            esc(ev.get("detail")))
        for ev in prov)
    return ('<div class="card"><h3>%s</h3><p>by %s</p><p>%s</p>'
            '<dl class="kv">'
            '<dt>Status</dt><dd>%s</dd>'
            '<dt>Tag ID</dt><dd class="mono">%s</dd>'
            '</dl>'
            '<h3 style="margin-top:18px">Provenance</h3>'
            '<ul class="timeline">%s</ul></div>' % (
                esc(product["name"]), esc(product["creator"]),
                esc(product["description"]),
                verdict_pill(product.get("verdict"),
                             product.get("status")),
                esc(product["tag_id"]),
                prov_html or '<li class="dim">No provenance recorded.</li>'))


def _check_detail_text(c, text_key):
    text = c.get(text_key) or c.get("detail") or c.get("reason") or ""
    validation = c.get("validation")
    if isinstance(validation, dict):
        bits = ["Validation: %s."
                % str(validation.get("status") or "").replace(
                    "_", " ")]
        if validation.get("signer_subject"):
            bits.append("Signer as presented: %s."
                        % validation["signer_subject"])
        extra = " ".join(bits)
        text = ("%s %s" % (text, extra)) if text else extra
    if c.get("check") == "media_probe" and not text:
        bits = []
        if c.get("container"):
            bits.append(str(c["container"]))
        if c.get("duration_ms") is not None:
            bits.append("%d ms" % c["duration_ms"])
        codec = c.get("video_codec") or c.get("codec") \
            or c.get("audio_codec")
        if codec:
            bits.append(str(codec))
        if c.get("width") and c.get("height"):
            bits.append("%d x %d" % (c["width"], c["height"]))
        if c.get("sample_rate"):
            bits.append("%d Hz" % c["sample_rate"])
        text = ", ".join(bits)
    return text or str(c.get("status") or "").replace("_", " ")


def _checks_list_html(title, entries, text_key):
    if not entries:
        return ""
    items = "".join(
        '<li><strong>%s</strong>: %s</li>' % (
            esc(str(c.get("check", "")).replace("_", " ")),
            esc(_check_detail_text(c, text_key)))
        for c in entries if isinstance(c, dict))
    if not items:
        return ""
    return "<h3>%s</h3><ul class=\"checklist\">%s</ul>" % (
        esc(title), items)


def registration_result(rec, verification_request=None,
                        api_base=PUBLIC_API_BASE):
    """Render a signed registration record (npc.registry.*).

    verification_request is the record's request state as the API
    reports it (GET /v1/records/{id}/verification-request), or None
    when the state could not be read: a requested record shows the
    fact and the date, an unrequested one shows the ask, and an
    unread state shows neither rather than guessing.
    """
    title = rec.get("title") or rec.get("agent_name") \
        or rec.get("record_id") or ""
    rows = [
        '<dt>Status</dt><dd>Registered, checks pending</dd>',
        '<dt>Record ID</dt><dd class="mono">%s</dd>'
        % esc(rec.get("record_id")),
    ]
    if isinstance(verification_request, dict) and \
            verification_request.get("verification_requested"):
        rows.append('<dt>Verification</dt><dd>Requested %s</dd>'
                    % esc(verification_request.get("requested_at")))
    if rec.get("kind") == "agent":
        rows.append('<dt>Agent</dt><dd>%s</dd>' % esc(rec.get("agent_name")))
        rows.append('<dt>Owner</dt><dd>%s</dd>' % esc(rec.get("owner_name")))
        if rec.get("homepage"):
            rows.append('<dt>Homepage</dt><dd>%s</dd>'
                        % esc(rec.get("homepage")))
        if rec.get("description"):
            rows.append('<dt>About</dt><dd>%s</dd>'
                        % esc(rec.get("description")))
    else:
        rows.append('<dt>Kind</dt><dd>%s</dd>'
                    % esc(rec.get("content_kind")))
        rows.append('<dt>Creator</dt><dd>%s</dd>'
                    % esc(rec.get("creator_name")))
        rows.append('<dt>Locator</dt><dd class="mono">%s</dd>'
                    % esc(rec.get("locator")))
    rows.append('<dt>Registered</dt><dd>%s</dd>'
                % esc(rec.get("registered_at")))
    if rec.get("signature"):
        rows.append('<dt>Signature</dt><dd class="mono">%s</dd>'
                    % esc(rec.get("signature")))
    ask = ""
    if isinstance(verification_request, dict) and \
            not verification_request.get("verification_requested"):
        ask = request_verification_html(rec.get("record_id"),
                                        api_base)
    # The identity panel container: filled by IDENTITY_PANEL_JS from
    # the API's panel endpoint when the record has linked identity
    # checks and the linking service is enabled; stays empty
    # otherwise, so no section appears for records without links.
    panel_slot = ('<div class="npc-identity-panel" '
                  'data-record-id="%s" data-api-base="%s"></div>'
                  % (esc(rec.get("record_id")), esc(api_base)))
    body = ('<div class="card"><h3>%s</h3>'
            '<p>A registration record, signed by NPC at issuance. '
            'Registration is not verification.</p>'
            '<dl class="kv">%s</dl>%s%s%s%s%s'
            '<p>Signed with key <span class="mono">%s</span>. The public '
            'keys are published in Search, so this record can be '
            'confirmed independently.</p></div>' % (
                esc(title), "".join(rows),
                _checks_list_html("Checks that ran",
                                  rec.get("checks_run"), "detail"),
                _checks_list_html("Checks that have not run yet",
                                  rec.get("checks_not_run"), "reason"),
                kya_html(rec) if rec.get("kind") == "agent" else "",
                panel_slot,
                ask,
                esc(rec.get("key_id"))))
    return body


def record_result(rec, verification_request=None,
                  api_base=PUBLIC_API_BASE):
    """Render any other record body GET /v1/records/{id} can return.

    Credentials and products are rendered by their dedicated views
    earlier in Search; this covers registration records, attestation
    records, and agent attestation records.
    """
    if not isinstance(rec, dict):
        return ""
    if str(rec.get("record_type") or "").startswith("npc.registry."):
        return registration_result(
            rec, verification_request=verification_request,
            api_base=api_base)
    if "subject_type" in rec and "verdict" in rec:
        return ('<div class="card"><h3>%s</h3>'
                '<dl class="kv">'
                '<dt>Result</dt><dd>%s</dd>'
                '<dt>Record ID</dt><dd class="mono">%s</dd>'
                '<dt>Tested</dt><dd>%s</dd>'
                '<dt>Findings</dt><dd>%s</dd>'
                '</dl>%s</div>' % (
                    esc(rec.get("subject_id")),
                    verdict_pill(rec.get("verdict")),
                    esc(rec.get("id")), esc(rec.get("tested_at")),
                    esc(rec.get("findings_summary")),
                    kya_html(rec)
                    if rec.get("subject_type") == "agent" else ""))
    if "agent_id" in rec and "verdict" in rec:
        return ('<div class="card"><h3>agent %s</h3>'
                '<dl class="kv">'
                '<dt>Result</dt><dd>%s</dd>'
                '<dt>Attestation</dt><dd class="mono">%s</dd>'
                '<dt>Notes</dt><dd>%s</dd>'
                '</dl>%s</div>' % (
                    esc(rec.get("agent_id")),
                    verdict_pill(rec.get("verdict")),
                    esc(rec.get("attestation_id")),
                    esc(rec.get("notes")),
                    kya_html(rec)))
    return ""


def verify_view(api_base=PUBLIC_API_BASE):
    return """
<div id="npc-verify" data-api-base="%s">
<p class="kicker">Verify yours</p>
<h1>Start verification of your own work.</h1>
<p class="lede">Registration is how verification starts. Register a piece of your work, or an agent you run, and NPC issues a signed record with its own NPC ID on the spot, at the status registered, checks pending. Registration is not verification, and no verification mark comes with it.</p>
<p id="npc-service-status">Registration is free, and every registration is issued as a signed NPC record with its own ID, on the spot.</p>
<div class="notice" id="npc-service-down" hidden>
<h3>The verification service is not answering yet</h3>
<p>Registrations are paused right now. Nothing you type is sent or saved while the service is down. <a href="/">Join the waitlist on the home page</a> to hear when registration opens.</p>
</div>
<noscript><div class="notice"><h3>Registration needs JavaScript</h3>
<p>With JavaScript off, the forms cannot reach the verification service. You can still <a href="/">join the waitlist</a>, or write to <a href="mailto:hello@npclabs.xyz">hello@npclabs.xyz</a>.</p></div></noscript>
<div class="notice" id="npc-register-error" hidden><h3>Not registered</h3><p id="npc-register-error-text"></p></div>
<div class="card" id="npc-register-result" hidden></div>

<h2>Register a piece of work</h2>
<p>Give the work a title, its kind, and where it can be found: a web address, or its content hash if you already have one. For a file at a web address, the first checks can run as you register: a read of any Content Credentials in the file with cryptographic validation when a manifest is present, the AI image check on images, and the container facts on audio and video. What ran, and what has not run yet, is written into the record itself.</p>
<form class="reg" id="npc-content-form">
<label class="small" for="npc-c-title">Title</label>
<input type="text" id="npc-c-title" name="title" required maxlength="200">
<label class="small" for="npc-c-kind">Kind</label>
<select id="npc-c-kind" name="kind">
<option value="image">Image</option>
<option value="text">Text</option>
<option value="audio">Audio</option>
<option value="video">Video</option>
<option value="other">Other</option>
</select>
<label class="small" for="npc-c-locator">Where it can be found: a web address, or a content hash</label>
<input type="text" id="npc-c-locator" name="locator" required maxlength="2048">
<label class="small" for="npc-c-name">Your name</label>
<input type="text" id="npc-c-name" name="creator_name" required maxlength="128">
<label class="small" for="npc-c-email">Your email</label>
<input type="email" id="npc-c-email" name="creator_email" required maxlength="254">
<button type="submit">Register this work</button>
</form>
<p class="examples">Your email ties the registration to you and keeps submissions fair. It is never published in the record.</p>

<h2>Register an agent</h2>
<p>Every agent in the registry has a named owner who is accountable for it. Registration is free. The signed record covers the registration itself. Verification is a separate step that follows: the checks run against the agent, and the record is updated when they complete. Until then, the record shows the agent as registered, checks pending.</p>
<form class="reg" id="npc-agent-form">
<label class="small" for="npc-a-name">Agent name</label>
<input type="text" id="npc-a-name" name="agent_name" required maxlength="128">
<label class="small" for="npc-a-owner">Owner name (a person, accountable for this agent)</label>
<input type="text" id="npc-a-owner" name="owner_name" required maxlength="128">
<label class="small" for="npc-a-email">Owner email</label>
<input type="email" id="npc-a-email" name="owner_email" required maxlength="254">
<label class="small" for="npc-a-home">Agent homepage (optional if you describe it instead)</label>
<input type="text" id="npc-a-home" name="homepage" maxlength="2048">
<label class="small" for="npc-a-desc">What the agent does (optional if you gave a homepage)</label>
<textarea id="npc-a-desc" name="description" maxlength="2000"></textarea>
<button type="submit">Register this agent</button>
</form>

<h2>After you register</h2>
<p>Your record lives in <a href="/search">Search</a> under its NPC ID, next to every other record, and anyone you share the ID with can pull it up. <a href="/help">How it works</a> explains how to read a record and what happens as the remaining checks run.</p>
</div>
<script>%s</script>
<script>%s</script>
""" % (esc(api_base), VERIFY_JS, REQUEST_VERIFY_JS)


def key_entries(keys_doc):
    """Flatten the published key document into (entry, label) pairs."""
    if not isinstance(keys_doc, dict):
        return []
    entries = []
    signing = keys_doc.get("api_signing") or {}
    cur = signing.get("current")
    if cur:
        entries.append((cur, "Active"))
    for entry in signing.get("history", []) or []:
        entries.append((entry, "Retired"))
    for entry in keys_doc.get("issuers", []) or []:
        entries.append((entry, "Active" if entry.get("status") == "active"
                        else "Retired"))
    return entries


def _search_example_links(values):
    return " ".join(
        '<a href="/search?id=%s">%s</a>' % (esc(value), esc(value))
        for value in values)


def search_view(query="", result_html="", credential_examples=(),
                product_examples=(), keys_doc=None, live_lookup_id=None,
                api_base=PUBLIC_API_BASE):
    parts = ["""
<p class="kicker">Search</p>
<h1>Look up any NPC ID.</h1>
<p class="lede">One search covers digital and physical IDs: credential IDs, product tag IDs, archive item IDs, public key IDs, and the IDs issued when you register your own work or agents. Enter an ID exactly as it appears on a certificate, a tag, a record, or a key.</p>
""", _search_form(query)]
    if live_lookup_id:
        parts.append(live_lookup_marker(api_base, live_lookup_id))
    if result_html:
        parts.append(result_html)
    parts.append("""
<h2>Sample IDs</h2>
<p>The samples below show how Search answers. They are test records, not real products, credentials, or people.</p>
""")
    if credential_examples:
        parts.append('<h3>Digital IDs</h3><p class="examples">%s</p>'
                     % _search_example_links(credential_examples))
    if product_examples:
        parts.append('<h3>Physical IDs</h3><p class="examples">%s</p>'
                     % _search_example_links(product_examples))
    parts.append("""
<p>Archive item IDs work here too: enter any historical item ID from the archive, and Search will find its record.</p>

<h2>Public keys</h2>
<p>Enter a key ID here, or open the full list. The keys let anyone confirm that a signed answer came from NPC.</p>
""")
    entries = key_entries(keys_doc)
    if entries:
        parts.append('<p class="examples">Published keys: %s</p>'
                     % _search_example_links(
                         [entry.get("key_id") for entry, _ in entries]))
    parts.append("""
<p><a href="/search/keys">Open the full public key list</a></p>

<h2>Verify yours</h2>
<p>Your own work and your own agents belong in this record too. On the <a href="/verify">Verify yours page</a> you can register a piece of work or an agent and start its verification: NPC issues a signed record with its own NPC ID, the first checks run, and the rest are listed as pending in the record itself. Registration is not verification, and it is free. If the verification service is not answering yet, the waitlist is the way to hear when registration opens.</p>
<p><a href="/verify">Start on the Verify yours page</a></p>
""")
    return "".join(parts)


def search_keys_view(keys_doc=None, query=""):
    parts = ["""
<p class="kicker">Search</p>
<h1>Public keys.</h1>
<p class="lede">Every signed answer can be checked against the public keys below. Enter a key ID in Search, or read the full list here. Old keys stay published after they retire, so old answers stay checkable.</p>
""", _search_form(query)]
    if keys_doc is None:
        parts.append(unavailable_notice())
        return "".join(parts)
    cur = (keys_doc.get("api_signing") or {}).get("current")
    hist = (keys_doc.get("api_signing") or {}).get("history", [])
    issuers = keys_doc.get("issuers", [])
    if cur:
        parts.append("<h2>Current signing key</h2>")
        parts.append(key_card(cur, "Active", anchor=True))
    if hist:
        parts.append("<h2>Retired signing keys</h2>"
                     "<p>Old signatures stay checkable. Retired keys are kept, never deleted.</p>")
        for entry in hist:
            parts.append(key_card(entry, "Retired", anchor=True))
    if issuers:
        parts.append("<h2>Issuer keys</h2>"
                     "<p>These keys sign the attestation records themselves.</p>")
        for entry in issuers:
            parts.append(key_card(
                entry, "Active" if entry.get("status") == "active" else "Retired",
                anchor=True))
    parts.append('<p><a href="/search">Back to Search</a></p>')
    return "".join(parts)


def search_unknown_view(query="", api_base=PUBLIC_API_BASE):
    # The verdict (head + notice) renders in full, so a visitor
    # without JavaScript still gets the honest answer. When the
    # live lookup runs, its script swaps the verdict for the
    # neutral pending notice below until the API answers, then
    # shows the record or restores the verdict. Nothing declares
    # an ID unknown while its lookup is still in flight.
    return """
<p class="kicker">Search</p>
<div id="npc-unknown-head">
<h1>Unknown.</h1>
<p class="lede">We have no record of this ID. That means unknown, not false. We never guess.</p>
</div>
%s
<div class="notice" id="npc-unknown-notice"><h3>Unknown</h3><p>Check the ID and try again, or <a href="/records">browse Records</a> to see what has been attested.</p>%s</div>
<div class="notice" id="npc-lookup-pending" hidden><h3>Looking up this ID…</h3><p>NPC is checking the record for this ID. The answer follows what the record says, never a guess.</p></div>
%s
""" % (_search_form(query), registration_invitation(),
       live_lookup_marker(api_base, query or None))


def archive_view(rows):
    parts = ["""
<p class="kicker">Records · Archive</p>
<h1>Company history, on chain.</h1>
<p class="lede">These records are real. Between 2023 and 2024, NPC Labs minted a small number of items on chain: merchandise from an early drop, a tokenized prescription product, the company's own first token, and two collections issued on Zora. They are kept here as history, the way a company keeps its first products on a shelf.</p>
<p>They are not current offerings, and they are not samples. Each one is backed by its on-chain record: chain, contract, token, and mint date are in the full record, with a link to the item. The first records below were minted to the NPC Labs wallet, <span class="mono">0xe8AFB7C355B68A2A9C616E7877D0ef3352c59D5a</span>, and none has moved since. The Zora collections are different, and their records say so: the Jordan Donald tokens were minted to collectors, and the Mysteria Luna series was configured on chain and never minted.</p>
"""]
    if rows:
        parts.append('<table><tr><th>Item</th><th>Collection</th>'
                     '<th>Chain</th><th>Token</th><th>Minted</th>'
                     '<th>Status</th><th></th></tr>')
        for r in rows:
            parts.append(
                '<tr><td>%s</td><td class="dim">%s</td><td class="dim">%s</td>'
                '<td class="dim">%s %s</td><td class="dim">%s</td><td>%s</td>'
                '<td><a href="/search?id=%s">Full record</a></td></tr>' % (
                    esc(r["name"]), esc(r["collection"]), esc(r["chain"]),
                    esc(r["standard"]), esc(r["token_id"]),
                    esc(r["minted_at"]), verdict_pill(None, r["status"]),
                    esc(r["tag_id"])))
        parts.append("</table>")
    else:
        parts.append(unavailable_notice(
            "No archive records could be confirmed right now."))
    parts.append('<p class="examples">Archive records are historical '
                 'mints. Current credential, product, archive, and key IDs '
                 'are looked up in Search.</p>')
    return "".join(parts)


def key_card(entry, label, anchor=False):
    return ('<div class="keybox"%s>' % ((' id="' + esc(entry.get("key_id")) + '"') if anchor else "") +
            '<p style="margin:0 0 4px"><strong>%s</strong> '
            '<span class="pill">%s</span></p>'
            '<p class="mono" style="margin:4px 0">%s</p>'
            '<p class="dim" style="margin:4px 0;font-size:13px">Ed25519. '
            'Created %s%s.</p></div>' % (
                esc(entry.get("key_id")), esc(label),
                esc(entry.get("public_key")),
                esc(entry.get("created_at")),
                (". Retired " + esc(entry.get("retired_at")))
                if entry.get("retired_at") else ""))


def help_view(api_base=PUBLIC_API_BASE):
    ask_biblo = ""
    if CHAT_WIDGET_ENABLED:
        ask_biblo = ("""
<h2>Ask Biblo</h2>
<p>Biblo is the assistant here. Ask it about records, registering your own work or an agent, what the checks mean, or where the plugins stand. It answers from these public pages and NPC's published articles, and it says plainly when it does not know. It cannot look a record up: Search is where a record speaks.</p>
""" + chat_panel_html(api_base, floating=False))
    return ("""
<p class="kicker">Help</p>
<h1>How it works</h1>
<p class="lede">Verified by NPC is a public record you can read and a search you can use. Records shows what has been attested. Search finds a credential, product, archive item, or public key by its ID. Every answer comes from a signed record, never from a guess.</p>
""" + ask_biblo + """
<h2>Start with what you have</h2>
<div class="row">
<div class="card"><h3><a href="/records">Records</a></h3>
<p>Browse signed statements about claims and agents: what was checked, when, and what the findings were.</p></div>
<div class="card"><h3><a href="/search">Search</a></h3>
<p>Enter any NPC ID in one place: a credential ID, a product tag ID, an archive item ID, or a public key ID.</p></div>
<div class="card"><h3><a href="/archive">The archive</a></h3>
<p>Real NPC Labs items minted on chain in 2023 and 2024, kept as company history.</p></div>
<div class="card"><h3><a href="/plugins">Plugins</a></h3>
<p>See where each assistant integration stands. Three are live today.</p></div>
</div>

<h2>Reading a result</h2>
<p>Every answer is one of a few plain words. <strong>Verified</strong> and <strong>authentic</strong> mean the record was checked and held up. <strong>Verified with caveats</strong> means it held up, and the record carries notes worth reading alongside it. <strong>Revoked</strong>, <strong>expired</strong>, and <strong>counterfeit</strong> mean the record says the thing should not be trusted as presented. <strong>Unknown</strong> means we have no record of it. Unknown is not a verdict; it is an honest answer, and we never guess to fill the gap.</p>
<p>A record shows what was checked, when it was checked, the scope it was checked under, and the findings in plain form. Where a credential holder kept their name private, the record respects that and shows no name.</p>
<p>The NPC check comes in two colors. A blue check marks a verified human. An orange check marks a verified agent or a verified product. The color tells you what kind of thing was verified; the record behind it tells you the rest.</p>

<h2>Public keys live in Search</h2>
<p>Enter a key ID in <a href="/search">Search</a>, or open the full public key list from that page. Anyone can use the published keys to confirm that a signed answer came from NPC, without an account and without taking our word for the connection. Old keys stay published after they retire, so old answers stay checkable.</p>

<h2>These are sample records</h2>
<p>The products, credentials, and records shown are test samples, labeled as such, so you can see exactly how an answer looks before anything of yours is on the line. Nothing among them is a real product, credential, or person. The archive is the exception: those are real items from NPC Labs' own history.</p>

<h2>Verify and register your own digital resources and agents</h2>
<p>You can start that here, on the <a href="/verify">Verify yours</a> page. Registration is the first step of verification: you give the work or the agent, your name, and your email, and NPC issues a signed record with its own NPC ID and the status "registered, checks pending". From that moment the record exists, and anyone can find it in Search by its ID.</p>
<p>Registration is not verification. The record lists which checks ran when you registered and which have not run yet, and no verification mark is issued at registration. For a file at a web address, some checks can run on the spot. An image is read for Content Credentials, and when a manifest is present it is validated cryptographically: the signature is verified, the assertions are checked against the claim, and the file is checked against its recorded hash. The signer is reported exactly as its certificate presents it; NPC does not rate signers. The AI image check can run on images too, and its answer is a signal, never a stamp. Audio and video files have their container facts read at registration: format, length, and codecs, with dimensions for video and channels and sample rate for audio. A video file's Content Credentials are read and validated the same way as an image's. Checks that need video frames or a person's review stay listed as pending until they happen. When you are ready for the remaining checks, you can request verification from your record in Search, using the email you registered with.</p>
<p>Registration is free, and it takes a minute. Nothing is registered until you see your NPC ID: if you do not see one, nothing was sent. If the verification service is not answering yet, the waitlist on the <a href="/">home page</a> is the way to hear when registration opens.</p>

<h2>NPC Verify and the extension</h2>
<p>NPC Verify is the same checking, pointed at images. When you register an image on the <a href="/verify">Verify yours</a> page, the checks that can run at intake run then, and their results are written into your record. The NPC Verify browser extension will bring the check to pages you browse: it asks whether an image is registered with NPC Labs, reads the image's embedded file information on your own device, and shows a signed answer it has confirmed before showing it to you. The extension is coming soon. The <a href="/privacy">privacy policy</a> describes exactly what it does with data.</p>

<h2>The AI image check is a signal</h2>
<p>One check deserves plain words. When NPC Verify is available, its AI image check will answer with a percentage: how likely it is that an image was generated by AI. Read it as a signal, not a verdict. A high percentage is a reason to look closer; a low one is not proof an image is human-made. No honest checker can give you certainty here, and when the checker cannot run, it should say so instead of inventing a number.</p>

<h2>Plugins</h2>
<p>The <a href="/plugins">Plugins page</a> tracks each one. Three are live today: the ChatGPT plugin, the Gemini extension, and the MCP server. Copilot is in enrollment with Microsoft. Each live integration answers against live records through the public API, and the full answer waits on the record itself. Join the waitlist to hear plugin news.</p>

<h2>The waitlist</h2>
<p>New surfaces land in stages. Joining the waitlist on the <a href="/">home page</a> puts you first to know when the NPC Verify extension, the Verified Agent Library, the Verified Agent Builder, plugin availability, and new releases arrive.</p>

<h2>Questions</h2>
<div class="card"><h3>What can I search?</h3>
<p>Any NPC ID: a credential ID from a certificate, a product tag ID from a physical item, an archive item ID, or a public key ID. Digital and physical IDs share one search because the question is the same: what does the record say?</p></div>
<div class="card"><h3>What if something has no record?</h3>
<p>The answer is unknown. That means we have no record of it. It does not mean the thing is fake, and it does not mean it is real. We would rather say unknown than guess.</p></div>
<div class="card"><h3>Where is the archive?</h3>
<p>Under Records. The archive holds NPC Labs' own historical items, minted on chain in 2023 and 2024, kept as company history. For a current lookup, use Search.</p></div>
<div class="card"><h3>Where do I find the public keys?</h3>
<p>In Search. Enter a key ID to look one up, or open the full public key list from the Search page, where anyone can read it.</p></div>
<div class="card"><h3>Can I verify or register my own digital resources or agents?</h3>
<p>Yes. Registration starts on the <a href="/verify">Verify yours</a> page: you register the work or the agent, NPC issues a signed record with its own NPC ID, and the checks begin. Registration is the start of verification, not the result. The record says which checks ran and which are still pending, and no verification mark is issued at registration.</p></div>
<div class="card"><h3>What do the two check colors mean?</h3>
<p>Blue marks a verified human. Orange marks a verified agent or a verified product. Same standard, two kinds of subjects.</p></div>
<div class="card"><h3>Are the records on this site real?</h3>
<p>The products, credentials, and test records are samples, built so you can see how the site answers. They are labeled as samples wherever they appear. The archive is different: real NPC Labs items minted on chain in 2023 and 2024, kept as company history.</p></div>
<div class="card"><h3>What does the AI image check actually tell me?</h3>
<p>When it is available, a percentage likelihood that an image was AI-generated. It is one signal with real uncertainty, useful for deciding what deserves a closer look. It is never a hard stamp of real or fake, from us or from anyone.</p></div>
<div class="card"><h3>What does "verified with caveats" mean?</h3>
<p>The record held up, and the record itself carries conditions or limits, shown next to the result. Read them; they are part of the answer, not fine print.</p></div>
<div class="card"><h3>Can I check an answer myself?</h3>
<p>Yes. Answers are signed, and the public keys are published in Search. Anyone can confirm a signature with them, without an account and without asking us.</p></div>
<div class="card"><h3>How do I get something listed or verified?</h3>
<p>Start with registration on the <a href="/verify">Verify yours</a> page. That puts your work or your agent on record with its own NPC ID and starts its verification. A record becomes verified only when the checks behind it have run and held up; registration alone never carries the mark. If the verification service is not answering yet, the waitlist on the <a href="/">home page</a> is the way to hear when it opens, or write to us at <a href="mailto:hello@npclabs.xyz">hello@npclabs.xyz</a>.</p></div>
""")

def not_found_view():
    return ('<p class="kicker">404</p><h1>Nothing here.</h1>'
            '<p class="lede">The page you asked for does not exist. '
            '<a href="/">Back to the start</a>.</p>')
