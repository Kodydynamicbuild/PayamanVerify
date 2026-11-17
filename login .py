# Step 1: member clicked Verify on the website -> send them to Discord's "Authorize" page.
import os
import secrets
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlencode, urlparse


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        panel = (parse_qs(urlparse(self.path).query).get("p") or [""])[0]
        if not panel or len(panel) > 200:
            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return

        host = self.headers.get("Host", "")
        redirect_uri = os.environ.get("REDIRECT_URI") or f"https://{host}/callback"
        state = secrets.token_hex(16)
        url = "https://discord.com/oauth2/authorize?" + urlencode({
            "client_id": os.environ["CLIENT_ID"],
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": "identify",
            "state": state,
            "prompt": "none",
        })
        secure = "; Secure" if redirect_uri.startswith("https://") else ""
        self.send_response(302)
        self.send_header("Location", url)
        # Remembers which panel they came from + protects against forged callbacks.
        self.send_header("Set-Cookie", f"vstate={state}~{panel}; HttpOnly; SameSite=Lax; Path=/; Max-Age=600{secure}")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

