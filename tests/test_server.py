import json
import threading
import urllib.error
import urllib.request
from http.server import HTTPServer

import pytest

from auth import server


@pytest.fixture
def base_url(tmp_path, monkeypatch):
    """Start the server on a random port in a thread; chdir to tmp so data is isolated."""
    monkeypatch.chdir(tmp_path)
    httpd = HTTPServer(("localhost", 0), server.Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://localhost:{httpd.server_port}"
    httpd.shutdown()
    thread.join()


def request(method, url, payload=None, token=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def register(base_url, username="budi", password="secret123"):
    return request("POST", f"{base_url}/register", {"username": username, "password": password})


def login(base_url, username="budi", password="secret123"):
    return request("POST", f"{base_url}/login", {"username": username, "password": password})


def test_register_then_login_then_me(base_url):
    status, body = register(base_url)
    assert status == 201
    assert body == {"username": "budi"}

    status, body = login(base_url)
    assert status == 200
    token = body["token"]

    status, body = request("GET", f"{base_url}/me", token=token)
    assert status == 200
    assert body == {"username": "budi"}


def test_duplicate_username_conflicts(base_url):
    register(base_url)
    assert register(base_url)[0] == 409


def test_login_with_wrong_password(base_url):
    register(base_url)
    assert login(base_url, password="wrong")[0] == 401


def test_login_unknown_user(base_url):
    assert login(base_url, username="ghost")[0] == 401


def test_register_requires_both_fields(base_url):
    assert request("POST", f"{base_url}/register", {"username": "budi"})[0] == 400
    assert request("POST", f"{base_url}/register", {})[0] == 400


def test_me_requires_a_token(base_url):
    assert request("GET", f"{base_url}/me")[0] == 401


def test_me_rejects_a_tampered_token(base_url):
    register(base_url)
    token = login(base_url)[1]["token"]
    assert request("GET", f"{base_url}/me", token=token + "XXX")[0] == 401


def test_password_is_not_stored_plain(base_url):
    register(base_url)
    with open("users.json") as f:
        raw = f.read()
    assert "secret123" not in raw
    assert "scrypt$" in raw
