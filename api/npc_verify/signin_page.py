"""The NPC account sign-in page (Gate G1).

Served by the API at GET /auth/sign-in. This is the browser side of
the unified login: the page runs the passkey ceremonies with the
browser's credential API, offers the one-time email link, accepts a
recovery code, and, after a sign-in, offers passkey enrollment and
shows the account's signed-in devices with revoke controls.

It is also the page the desktop app's browser handoff opens. The
handoff id rides in the query string and is passed through the
sign-in calls, so a completed sign-in readies the handoff for the
app to exchange. The page itself holds the web surface's session
token in sessionStorage, which is that surface's own credential,
the same standing a browser session cookie would have.

The page is not a record, so it is served unsigned, like chat.
Styling is deliberately plain: NPC orange accent, Georgia serif,
no build step and no external assets.
"""

PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in to NPC</title>
<style>
  body { margin:0; padding:24px; font-family:Georgia,serif; color:#23201B; background:#FFFFFD; }
  .wrap { max-width:520px; margin:0 auto; }
  h1 { font-size:26px; font-weight:normal; }
  h2 { font-size:19px; font-weight:normal; margin-top:32px; }
  .accent { color:#ec662b; }
  p { line-height:1.5; }
  label { display:block; margin:14px 0 6px; }
  input { width:100%; box-sizing:border-box; padding:10px; font-size:16px; border:1px solid #b9b2a4; border-radius:6px; font-family:inherit; }
  button { margin-top:14px; padding:10px 18px; font-size:16px; font-family:inherit; border:1px solid #23201B; border-radius:6px; background:#23201B; color:#FFFFFD; cursor:pointer; }
  button.secondary { background:#FFFFFD; color:#23201B; }
  button.small { padding:5px 12px; font-size:14px; margin-top:0; }
  .note { color:#6b655a; font-size:14px; }
  .error { color:#a12622; }
  .codes { font-family:Menlo,Consolas,monospace; font-size:15px; background:#f6f2e9; padding:14px 18px; border-radius:6px; line-height:1.9; }
  .device { border-top:1px solid #e4ded2; padding:10px 0; display:flex; justify-content:space-between; align-items:center; gap:12px; }
  .hidden { display:none; }
</style>
</head>
<body>
<div class="wrap">
  <h1>Sign in to <span class="accent">NPC</span></h1>

  <div id="view-loading"><p class="note">One moment.</p></div>

  <div id="view-signin" class="hidden">
    <p>One account works everywhere NPC does. Sign in with a passkey if you have one, or ask for a one-time link by email.</p>
    <label for="email">Email address</label>
    <input id="email" type="email" autocomplete="email" placeholder="you@example.com">
    <div>
      <button id="btn-passkey" type="button">Sign in with a passkey</button>
      <button id="btn-email" type="button" class="secondary">Email me a sign-in link</button>
    </div>
    <p id="email-note" class="note hidden">Your link is on its way. It works once and expires soon, so open it on this device when it arrives.</p>
    <h2>No passkey and no inbox access?</h2>
    <p class="note">Use one of the recovery codes you saved when you enrolled your first passkey.</p>
    <label for="recovery-code">Recovery code</label>
    <input id="recovery-code" type="text" autocomplete="off" placeholder="XXXX-XXXX-XXXX">
    <div><button id="btn-recovery" type="button" class="secondary">Sign in with a recovery code</button></div>
  </div>

  <div id="view-account" class="hidden">
    <p>Signed in as <strong id="account-email"></strong>.</p>
    <p id="handoff-note" class="note hidden">You can close this tab and go back to the desktop app. It signs in on its own from here.</p>
    <div id="enroll-box">
      <h2>Your passkey</h2>
      <p id="enroll-copy">Add a passkey to this account so signing in takes one touch, with nothing to remember and nothing to reuse.</p>
      <button id="btn-enroll" type="button">Add a passkey</button>
      <div id="codes-box" class="hidden">
        <p><strong>Save these recovery codes now.</strong> They are shown once. Each one signs you in a single time if you ever lose your passkeys, so keep them somewhere safe.</p>
        <div id="codes" class="codes"></div>
      </div>
    </div>
    <h2>Signed-in devices</h2>
    <p class="note">Every surface shows the same list. Revoking a device signs it out everywhere.</p>
    <div id="devices"></div>
    <div><button id="btn-signout" type="button" class="secondary">Sign out of this browser</button></div>
  </div>

  <p id="message" class="error hidden"></p>
</div>

<script>
"use strict";
var params = new URLSearchParams(window.location.search);
var handoffId = params.get("handoff") || "";
var linkToken = params.get("token") || "";
var sessionToken = sessionStorage.getItem("npc_account_session") || "";

function $(id) { return document.getElementById(id); }
function show(id) {
  ["view-loading", "view-signin", "view-account"].forEach(function (v) {
    $(v).classList.toggle("hidden", v !== id);
  });
}
function say(text) {
  var el = $("message");
  el.textContent = text || "";
  el.classList.toggle("hidden", !text);
}
function b64url(buf) {
  var bytes = new Uint8Array(buf), out = "";
  bytes.forEach(function (b) { out += String.fromCharCode(b); });
  return btoa(out).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function unb64url(text) {
  var pad = "=".repeat((4 - (text.length % 4)) % 4);
  var raw = atob(text.replace(/-/g, "+").replace(/_/g, "/") + pad);
  var buf = new Uint8Array(raw.length);
  for (var i = 0; i < raw.length; i++) buf[i] = raw.charCodeAt(i);
  return buf.buffer;
}
function deviceLabel() {
  var ua = navigator.userAgent || "";
  if (/Macintosh/.test(ua)) return "Web browser on a Mac";
  if (/Windows/.test(ua)) return "Web browser on Windows";
  if (/iPhone|iPad/.test(ua)) return "Web browser on an Apple mobile device";
  if (/Android/.test(ua)) return "Web browser on Android";
  if (/Linux/.test(ua)) return "Web browser on Linux";
  return "Web browser";
}
async function call(method, path, body, auth) {
  var headers = { "Content-Type": "application/json" };
  if (auth) headers["Authorization"] = "Bearer " + sessionToken;
  var res = await fetch(path, {
    method: method,
    headers: headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  var data = {};
  try { data = await res.json(); } catch (e) { data = {}; }
  if (!res.ok) {
    throw new Error(data.detail || data.error || "That did not work. Try again.");
  }
  return data;
}
function credentialPayload(cred, extra) {
  var payload = {
    id: cred.id,
    rawId: b64url(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: b64url(cred.response.clientDataJSON),
    },
  };
  if (cred.response.attestationObject) {
    payload.response.attestationObject = b64url(cred.response.attestationObject);
  }
  if (cred.response.authenticatorData) {
    payload.response.authenticatorData = b64url(cred.response.authenticatorData);
  }
  if (cred.response.signature) {
    payload.response.signature = b64url(cred.response.signature);
  }
  if (cred.response.userHandle) {
    payload.response.userHandle = b64url(cred.response.userHandle);
  }
  return Object.assign(payload, extra || {});
}
async function signedIn(data) {
  if (data.session_token) {
    sessionToken = data.session_token;
    sessionStorage.setItem("npc_account_session", sessionToken);
  }
  history.replaceState({}, "", window.location.pathname);
  await refreshAccount();
}
async function refreshAccount() {
  try {
    var me = await call("GET", "/v1/auth/me", null, true);
    $("account-email").textContent = me.account.email;
    $("handoff-note").classList.toggle("hidden", !handoffId);
    show("view-account");
    say("");
    await refreshDevices();
  } catch (e) {
    sessionToken = "";
    sessionStorage.removeItem("npc_account_session");
    show("view-signin");
  }
}
async function refreshDevices() {
  var box = $("devices");
  box.innerHTML = "";
  var data = await call("GET", "/v1/auth/sessions", null, true);
  data.sessions.forEach(function (s) {
    var row = document.createElement("div");
    row.className = "device";
    var left = document.createElement("div");
    left.textContent = (s.device_label || s.surface) + (s.current ? " (this one)" : "");
    var sub = document.createElement("div");
    sub.className = "note";
    sub.textContent = "Signed in " + s.created_at.replace("T", " ").replace("Z", " UTC");
    left.appendChild(sub);
    row.appendChild(left);
    if (!s.current) {
      var btn = document.createElement("button");
      btn.type = "button";
      btn.className = "secondary small";
      btn.textContent = "Revoke";
      btn.addEventListener("click", async function () {
        await call("POST", "/v1/auth/sessions/revoke", { session_id: s.session_id }, true);
        await refreshDevices();
      });
      row.appendChild(btn);
    }
    box.appendChild(row);
  });
}

$("btn-email").addEventListener("click", async function () {
  say("");
  try {
    await call("POST", "/v1/auth/email/request", {
      email: $("email").value, handoff_id: handoffId || undefined,
    });
    $("email-note").classList.remove("hidden");
  } catch (e) { say(e.message); }
});
$("btn-passkey").addEventListener("click", async function () {
  say("");
  try {
    var begin = await call("POST", "/v1/auth/passkeys/authenticate/begin", {
      email: $("email").value || undefined,
    });
    var pk = begin.publicKey;
    pk.challenge = unb64url(pk.challenge);
    pk.allowCredentials = (pk.allowCredentials || []).map(function (c) {
      return { type: c.type, id: unb64url(c.id) };
    });
    var cred = await navigator.credentials.get({ publicKey: pk });
    var data = await call("POST", "/v1/auth/passkeys/authenticate/finish",
      credentialPayload(cred, {
        challenge_id: begin.challenge_id,
        surface: "web",
        device_label: deviceLabel(),
        handoff_id: handoffId || undefined,
      }));
    await signedIn(data);
  } catch (e) { say(e.message); }
});
$("btn-recovery").addEventListener("click", async function () {
  say("");
  try {
    var data = await call("POST", "/v1/auth/recovery/redeem", {
      email: $("email").value,
      code: $("recovery-code").value,
      surface: "web",
      device_label: deviceLabel(),
    });
    await signedIn(data);
    say("You are signed in with a recovery code. Add a fresh passkey below so the next sign-in is one touch.");
  } catch (e) { say(e.message); }
});
$("btn-enroll").addEventListener("click", async function () {
  say("");
  try {
    var begin = await call("POST", "/v1/auth/passkeys/register/begin", {}, true);
    var pk = begin.publicKey;
    pk.challenge = unb64url(pk.challenge);
    pk.user.id = unb64url(pk.user.id);
    pk.excludeCredentials = (pk.excludeCredentials || []).map(function (c) {
      return { type: c.type, id: unb64url(c.id) };
    });
    var cred = await navigator.credentials.create({ publicKey: pk });
    var data = await call("POST", "/v1/auth/passkeys/register/finish",
      credentialPayload(cred, { challenge_id: begin.challenge_id }), true);
    if (data.recovery_codes) {
      $("codes").innerHTML = data.recovery_codes.map(function (c) {
        return "<div>" + c + "</div>";
      }).join("");
      $("codes-box").classList.remove("hidden");
    }
    $("enroll-copy").textContent = "Passkey added. A second passkey on another device is worth adding too, so one lost device never locks you out.";
  } catch (e) { say(e.message); }
});
$("btn-signout").addEventListener("click", async function () {
  try { await call("POST", "/v1/auth/sign-out", {}, true); } catch (e) { /* signing out locally regardless */ }
  sessionToken = "";
  sessionStorage.removeItem("npc_account_session");
  show("view-signin");
});

(async function start() {
  if (linkToken) {
    try {
      var data = await call("POST", "/v1/auth/email/redeem", {
        token: linkToken, surface: "web", device_label: deviceLabel(),
      });
      await signedIn(data);
      if (data.passkey_enrollment_recommended) {
        say("Welcome. Add a passkey below so the next sign-in is one touch.");
      }
      return;
    } catch (e) {
      say(e.message);
      show("view-signin");
      return;
    }
  }
  if (sessionToken) { await refreshAccount(); return; }
  show("view-signin");
})();
</script>
</body>
</html>
"""


def render_signin_page() -> str:
    return PAGE
