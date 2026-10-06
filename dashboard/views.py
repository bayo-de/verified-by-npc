"""HTML views for the Verified by NPC dashboard.

Restrained, quiet pages: system type, hairline rules, small-caps labels.
Copy explains the why, never the internal method. No em-dashes anywhere
in user-facing text. Every API-derived value is HTML-escaped at render.
"""
import html as _html

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
.top-in{display:flex;align-items:baseline;justify-content:space-between;flex-wrap:wrap;padding:18px 0;gap:12px}
.brand{color:var(--ink);text-decoration:none;font-weight:650;font-size:17px;letter-spacing:-0.01em}
nav a{color:var(--muted);text-decoration:none;font-size:14px;margin-left:20px}
nav a:hover{color:var(--ink)}
main{padding:44px 0 64px}
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
.examples{font-size:14px;color:var(--muted);margin-top:10px}
.examples a{margin-right:14px}
.scope{margin:2px 0}
.scope span{display:inline-block;background:#f4f4f2;border:1px solid var(--line);border-radius:6px;
  padding:2px 9px;margin:0 6px 6px 0;font-size:13px;color:var(--muted)}
"""


def esc(value):
    if value is None:
        return ""
    return _html.escape(str(value), quote=True)


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
<a href="/records">Records</a><a href="/credentials">Credentials</a><a href="/products">Products</a><a href="/keys">Keys</a><a href="/plugins">Plugins</a>
</nav>
</div></header>
<main class="wrap">
%s
</main>
<footer class="foot wrap">
<span>Internal preview. Local only.</span>
<span>Reading from %s</span>
</footer>
</body>
</html>""" % (esc(title), CSS, body, esc(api_url))


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


def unknown_notice(subject):
    return ('<div class="notice"><h3>Unknown</h3>'
            '<p>We have no record of %s. That means unknown, not false. '
            'We never guess.</p></div>' % esc(subject))


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
<p>People are asked to trust more than ever: a product listing, a certificate, a claim in a pitch, an agent asking for access. Trust should rest on something you can check, not on a logo or a promise. Every answer here is signed by NPC, and the keys to check those signatures are published on this site. If we do not know, we say unknown.</p>

<div class="row">
<div class="card"><h3><a href="/products">Products</a></h3>
<p>Check whether a product is authentic before you buy it.</p></div>
<div class="card"><h3><a href="/credentials">Credentials</a></h3>
<p>Check whether a certificate is real before you trust it.</p></div>
<div class="card"><h3><a href="/records">Records</a></h3>
<p>See what has actually been tested, and what the findings were.</p></div>
<div class="card"><h3><a href="/keys">Keys</a></h3>
<p>The public keys behind every signed answer. Check them yourself.</p></div>
</div>

<h2>How it reaches you</h2>
<p>The same records live inside the assistants people already use. The <a href="/plugins">plugins</a> answer "is this real?" mid-conversation in ChatGPT, Claude, Gemini, and Copilot, and point back here for the full record.</p>

<p class="examples">This preview reads from the local test fixtures. Nothing here is a real product, credential, or person.</p>
"""


def plugins_view():
    return """
<p class="kicker">Distribution</p>
<h1>The plugins meet people where they ask.</h1>
<p class="lede">Every "is this real?" moment inside an AI assistant resolves against the same records shown on this site. The plugin answers in the conversation and points here for the full verification record.</p>

<h2>What a plugin answers</h2>
<div class="card"><h3>Is this product authentic?</h3><p>Smart-tag lookup, with provenance.</p></div>
<div class="card"><h3>Is this certificate real?</h3><p>Credential lookup, with status and revocation.</p></div>
<div class="card"><h3>Did this really happen?</h3><p>Claim matched against attested records, findings shown, method never shown.</p></div>
<div class="card"><h3>Is this agent verified?</h3><p>Agent attestation: verdict, scope, and time bounds.</p></div>
<div class="card"><h3>What does Verified by NPC mean?</h3><p>A plain-language explainer. The why, never the how.</p></div>

<h2>Where they run</h2>
<table>
<tr><th>Assistant</th><th>Surface</th><th>Status</th></tr>
<tr><td>Claude</td><td class="dim">MCP server, works in any MCP client</td><td>Built, in local testing</td></tr>
<tr><td>ChatGPT</td><td class="dim">Plugin / GPT action</td><td>Awaiting the developer account gate</td></tr>
<tr><td>Gemini</td><td class="dim">Extension</td><td>Awaiting the developer account gate</td></tr>
<tr><td>Copilot</td><td class="dim">Plugin</td><td>Awaiting the partner account gate</td></tr>
</table>
<p class="examples">Plugin submissions, store listings, and the public endpoint all need explicit approval before they ship.</p>
"""


def records_view(rows, claim_result=None, claim_error=None):
    parts = ["""
<p class="kicker">Attestation records</p>
<h1>What has been tested.</h1>
<p class="lede">Each record is a signed statement about one subject: what was checked, when, and what the findings were. Only the sanitized findings are shown.</p>
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
<h2>Check a claim</h2>
<p>Type a claim exactly as stated. If it matches an attested record, the record is shown. Otherwise the answer is unknown.</p>
<form method="post" action="/records">
<label class="small" for="claim_text">Claim</label>
<textarea id="claim_text" name="claim_text" placeholder="e.g. The test widget passes drop testing"></textarea>
<div style="margin-top:10px"><button type="submit">Check</button></div>
</form>
""")
    if claim_result is not None:
        a = claim_result["attestation"]
        parts.append('<div class="card"><h3>Matched a record</h3>'
                     '<p>%s</p><dl class="kv">'
                     '<dt>Result</dt><dd>%s</dd>'
                     '<dt>Record</dt><dd class="mono">%s</dd>'
                     '<dt>Tested</dt><dd>%s</dd>'
                     '<dt>Findings</dt><dd>%s</dd>'
                     '</dl></div>' % (
                         esc(claim_result.get("claim_text", "")),
                         verdict_pill(a["verdict"]),
                         esc(a["id"]), esc(a["tested_at"]),
                         esc(a["findings_summary"])))
    if claim_error == "unknown":
        parts.append(unknown_notice("this claim"))
    elif claim_error == "unavailable":
        parts.append(unavailable_notice())
    parts.append('<p class="examples">Records shown are internal test fixtures.</p>')
    return "".join(parts)


def credentials_view(cred=None, state="form", examples=()):
    parts = ["""
<p class="kicker">Credentials</p>
<h1>Is this certificate real?</h1>
<p class="lede">Look up a credential by its ID. The status shown is the current one: valid, revoked, or expired. A holder name appears only if the holder made it public.</p>
<form class="lookup" method="get" action="/credentials">
<input type="text" name="id" placeholder="Credential ID" value="%s" aria-label="Credential ID">
<button type="submit">Look up</button>
</form>
""" % esc(cred["id"] if cred else "")]
    if examples:
        parts.append('<p class="examples">Try: %s</p>' % " ".join(
            '<a href="/credentials?id=%s">%s</a>' % (esc(e), esc(e))
            for e in examples))
    if state == "ok" and cred:
        parts.append('<div class="card"><h3>%s</h3><p>%s</p>'
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
    elif state == "unknown":
        parts.append(unknown_notice("this credential"))
    elif state == "unavailable":
        parts.append(unavailable_notice())
    return "".join(parts)


def products_view(product=None, state="form", examples=()):
    parts = ["""
<p class="kicker">Products</p>
<h1>Is this product authentic?</h1>
<p class="lede">Look up a product by its smart-tag ID. Authentic means the tag and the product record match. Anything else is reported exactly as found: counterfeit or unknown.</p>
<form class="lookup" method="get" action="/products">
<input type="text" name="tag" placeholder="Tag ID" value="%s" aria-label="Tag ID">
<button type="submit">Look up</button>
</form>
""" % esc(product["tag_id"] if product else "")]
    if examples:
        parts.append('<p class="examples">Try: %s</p>' % " ".join(
            '<a href="/products?tag=%s">%s</a>' % (esc(e), esc(e))
            for e in examples))
    if state == "ok" and product:
        prov = product.get("provenance") or []
        prov_html = "".join(
            '<li><span class="ev">%s</span><br>'
            '<span class="at">%s</span><br>'
            '<span class="dt">%s</span></li>' % (
                esc(ev.get("event")), esc(ev.get("at")),
                esc(ev.get("detail")))
            for ev in prov)
        parts.append('<div class="card"><h3>%s</h3><p>by %s</p><p>%s</p>'
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
    elif state == "unknown":
        parts.append(unknown_notice("this tag"))
    elif state == "unavailable":
        parts.append(unavailable_notice())
    return "".join(parts)


def keys_view(keys_doc):
    parts = ["""
<p class="kicker">Public keys</p>
<h1>Check our answers yourself.</h1>
<p class="lede">Every response from the verification API carries a signature. The keys below are the public halves. Anyone can use them to confirm a signature without trusting the connection.</p>
"""]
    cur = (keys_doc.get("api_signing") or {}).get("current")
    hist = (keys_doc.get("api_signing") or {}).get("history", [])
    issuers = keys_doc.get("issuers", [])
    if cur:
        parts.append("<h2>Current signing key</h2>")
        parts.append(key_card(cur, "Active"))
    if hist:
        parts.append("<h2>Retired signing keys</h2>"
                     "<p>Old signatures stay checkable. Retired keys are kept, never deleted.</p>")
        for k in hist:
            parts.append(key_card(k, "Retired"))
    if issuers:
        parts.append("<h2>Issuer keys</h2>"
                     "<p>These keys sign the attestation records themselves.</p>")
        for k in issuers:
            parts.append(key_card(k, "Active" if k.get("status") == "active" else "Retired"))
    return "".join(parts)


def key_card(entry, label):
    return ('<div class="keybox"><p style="margin:0 0 4px"><strong>%s</strong> '
            '<span class="pill">%s</span></p>'
            '<p class="mono" style="margin:4px 0">%s</p>'
            '<p class="dim" style="margin:4px 0;font-size:13px">Ed25519. '
            'Created %s%s.</p></div>' % (
                esc(entry.get("key_id")), esc(label),
                esc(entry.get("public_key")),
                esc(entry.get("created_at")),
                (". Retired " + esc(entry.get("retired_at")))
                if entry.get("retired_at") else ""))


def not_found_view():
    return ('<p class="kicker">404</p><h1>Nothing here.</h1>'
            '<p class="lede">The page you asked for does not exist. '
            '<a href="/">Back to the start</a>.</p>')
