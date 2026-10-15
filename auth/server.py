"""Auth API: three endpoints (register, login, me) plus a Bearer-token guard.

The HTTP skeleton is the same as the earlier REST repo (BaseHTTPRequestHandler).
"""

import json
from http.server import BaseHTTPRequestHandler, HTTPServer

from . import store
from .security import create_token, decode_token, verify_password

PORT = 8000


class Handler(BaseHTTPRequestHandler):
    """Handles each incoming request."""

    def _send(self, code, data):
        """Send a JSON response with the given status code."""
        body = json.dumps(data).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        """Read and parse the JSON request body. Return {} if empty."""
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        return json.loads(self.rfile.read(length))

    def _current_user(self):
        """Return the logged-in username from the Bearer token, or None if invalid.

        This is the auth middleware: it trusts the token's signature instead of
        looking the user up on every request.
        """
        # The token arrives in the Authorization header as "Bearer <token>".
        auth = self.headers.get("Authorization", "")

        # No header, or the wrong scheme -> not authenticated.
        if not auth.startswith("Bearer "):
            return None

        # Strip the scheme, then verify signature + expiry via decode_token.
        token = auth.removeprefix("Bearer ").strip()
        payload = decode_token(token)

        # Invalid or expired token -> reject.
        if payload is None:
            return None

        # Valid token -> the subject is the identity.
        return payload["sub"]

    def do_POST(self):
        # Read the JSON body once (used by both register and login).
        body = self._read_body()

        if self.path == "/register":
            username = body.get("username")
            password = body.get("password")
            if not username or not password:
                self._send(400, {"error": "username and password required"})
                return

            users = store.load()
            try:
                store.create_user(users, username, password)
            except ValueError:
                # Username already exists -> 409 Conflict.
                self._send(409, {"error": "username already taken"})
                return
            store.save(users)
            self._send(201, {"username": username})

        elif self.path == "/login":
            users = store.load()
            username = body.get("username")
            record = store.get_user(users, username)
            # The error is deliberately identical for "no such user" and "wrong
            # password", so an attacker cannot enumerate valid usernames.
            if record is None or not verify_password(body.get("password", ""), record["password_hash"]):
                self._send(401, {"error": "invalid credentials"})
                return
            # Credentials are good -> issue a token valid for one hour.
            token = create_token(username)
            self._send(200, {"token": token})

        else:
            self._send(404, {"error": "not found"})

    def do_GET(self):
        if self.path == "/me":
            # Protected route: run the guard before serving.
            username = self._current_user()
            if username is None:
                self._send(401, {"error": "unauthorized"})
                return
            self._send(200, {"username": username})
        else:
            self._send(404, {"error": "not found"})

    def log_message(self, *args):
        """Silence the default per-request logging."""
        pass


def run(port: int = PORT) -> None:
    """Start the server (blocking)."""
    server = HTTPServer(("localhost", port), Handler)
    print(f"Running at http://localhost:{port}")
    server.serve_forever()


if __name__ == "__main__":
    run()
