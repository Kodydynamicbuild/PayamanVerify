# Step 2: Discord sends the member back here after "Authorize".
# We learn who they are, give them the role, then send them back to Discord.
import base64
import hashlib
import hmac
import html
import json
import os
import secrets
import time
import urllib.error
import urllib.request
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlencode, urlparse

API = "https://discord.com/api/v10"
UA = "DiscordBot (https://vercel.com, 1.0)"
DISCORD_EPOCH_MS = 1420070400000

CSS = """
:root{--bg:#0f1117;--card:#181b24;--text:#e8eaf0;--muted:#9aa1b2;--accent:#6c7cff;--accent-2:#5866f0;--line:#2a2f3d}
@media (prefers-color-scheme:light){:root{--bg:#f4f5f9;--card:#fff;--text:#1b1e27;--muted:#5d6475;--line:#e2e5ee}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px 16px;font:16px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
background:var(--bg);color:var(--text);background-image:radial-gradient(circle at 20% 0%,rgba(108,124,255,.18),transparent 45%)}
.card{width:100%;max-width:440px;background:var(--card);border:1px solid var(--line);border-radius:18px;padding:32px 28px;box-shadow:0 20px 50px rgba(0,0,0,.25)}
.badge{width:56px;height:56px;border-radius:16px;display:grid;place-items:center;font-size:28px;margin-bottom:16px}
.ok{background:rgba(62,207,142,.15)}.bad{background:rgba(255,107,107,.15)}
h1{font-size:24px;margin:0 0 6px}p{color:var(--muted);margin:0 0 20px}
.btn{display:block;width:100%;text-align:center;text-decoration:none;border-radius:12px;padding:13px 16px;font-weight:600;color:#fff;background:var(--accent)}
.btn:hover{background:var(--accent-2)}
"""


def call(method, url, headers=None, data=None):
    """Small HTTP helper. Returns (status, parsed JSON or text)."""
    req = urllib.request.Request(url, method=method, data=data, headers={"User-Agent": UA, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            status, body = r.status, r.read()
    except urllib.error.HTTPError as e:
        status, body = e.code, e.read()
    try:
        return status, json.loads(body) if body else None
    except ValueError:
        return status, body.decode(errors="replace")


def read_panel(panel):
    """The panel link is guild.role.signature (made by the bot). Returns (guild_id, role_id) or None."""
    try:
        guild_id, role_id, sig = panel.split(".")
        expected = hmac.new(os.environ["VERIFY_SECRET"].encode(), f"panel.{guild_id}.{role_id}".encode(),
                            hashlib.sha256).digest()
        given = base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4))
        if not hmac.compare_digest(expected, given):
            return None
        return int(guild_id), int(role_id)
    except (ValueError, AttributeError):
        return None


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            self.verify()
        except Exception as e:  # never show a raw crash to members
            print("Unexpected error:", repr(e))
            self.fail("Something went wrong", "Please try again in a moment.", 500)

    # ---------- pages ----------
    def page(self, ok, title, message, status, guild_id=None):
        button, script = "", ""
        if guild_id:
            web = os.environ.get("SERVER_INVITE_URL") or f"https://discord.com/channels/{guild_id}"
            button = f'<a class="btn" href="{html.escape(web)}">Back to Discord</a>'
        if ok and guild_id:
            # Opens the Discord app automatically.
            script = f'<script>setTimeout(function(){{location.href="discord://-/channels/{int(guild_id)}"}},1500)</script>'
        body = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{html.escape(title)}</title><style>{CSS}</style></head>
<body><main class="card"><div class="badge {'ok' if ok else 'bad'}">{'✅' if ok else '⚠️'}</div>
<h1>{html.escape(title)}</h1><p>{html.escape(message)}</p>{button}</main>{script}</body></html>""".encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Set-Cookie", "vstate=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def fail(self, title, message, status=400, guild_id=None):
        self.page(False, title, message, status, guild_id)

    # ---------- the actual verification ----------
    def verify(self):
        env = os.environ
        q = {k: v[0] for k, v in parse_qs(urlparse(self.path).query).items()}
        if q.get("error"):
            return self.fail("Verification cancelled",
                             "You need to press Authorize to verify. Go back to Discord and click Verify again.")

        cookies = SimpleCookie(self.headers.get("Cookie") or "")
        saved = cookies["vstate"].value if "vstate" in cookies else ""
        saved_state, _, panel = saved.partition("~")
        state = q.get("state") or ""
        if not q.get("code") or not saved_state or not secrets.compare_digest(state, saved_state):
            return self.fail("Session expired", "Go back to Discord and click Verify again.")

        target = read_panel(panel)
        if target is None:
            return self.fail("Invalid link", "Open this page from the Verify button in the Discord server.")
        guild_id, role_id = target

        # 1. Swap the code for a token.
        redirect_uri = env.get("REDIRECT_URI") or f"https://{self.headers.get('Host', '')}/callback"
        status, token = call("POST", f"{API}/oauth2/token",
                             headers={"Content-Type": "application/x-www-form-urlencoded"},
                             data=urlencode({
                                 "grant_type": "authorization_code", "code": q["code"],
                                 "redirect_uri": redirect_uri,
                                 "client_id": env["CLIENT_ID"], "client_secret": env["CLIENT_SECRET"],
                             }).encode())
        if status != 200:
            print("Token exchange failed:", status, token)
            return self.fail("Something went wrong", "Discord did not accept the sign-in. Please try again.", 502)

        # 2. Find out who they are.
        status, user = call("GET", f"{API}/users/@me", headers={"Authorization": f"Bearer {token['access_token']}"})
        if status != 200:
            print("User lookup failed:", status, user)
            return self.fail("Something went wrong", "Could not read your Discord profile.", 502)
        user_id = int(user["id"])

        # 3. Optional: block brand-new (likely alt/spam) accounts.
        min_days = float(env.get("MIN_ACCOUNT_AGE_DAYS") or 0)
        if min_days > 0:
            age_days = (time.time() * 1000 - ((user_id >> 22) + DISCORD_EPOCH_MS)) / 86_400_000
            if age_days < min_days:
                print(f"Rejected {user['username']} ({user_id}): account {age_days:.1f} days old")
                return self.fail("Account too new",
                                 f"Your Discord account must be at least {min_days:g} days old to verify.", 403, guild_id)

        # 4. Give them the role with the bot token.
        status, err = call("PUT", f"{API}/guilds/{guild_id}/members/{user_id}/roles/{role_id}",
                           headers={"Authorization": f"Bot {env['BOT_TOKEN']}",
                                    "X-Audit-Log-Reason": "Verified through website"},
                           data=b"")
        if status == 204:
            print(f"Verified {user['username']} ({user_id})")
            return self.page(True, "You're verified!",
                             "Taking you back to Discord… The whole server is unlocked for you.", 200, guild_id)

        print("Role assign failed:", status, err)
        if status == 404 and isinstance(err, dict) and err.get("code") == 10007:  # Unknown Member
            return self.fail("You're not in the server",
                             "Join the Discord server first, then click Verify there again.", 404, guild_id)
        if status == 403:
            print("Fix: give the bot 'Manage Roles' and put its role ABOVE the Verified role")
        return self.fail("Something went wrong",
                         "The bot could not give you the role. Please tell a moderator.", 500, guild_id)
