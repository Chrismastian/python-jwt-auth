import time

import pytest

from auth import security, store


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------
def test_hash_is_not_the_password():
    """The stored value must never contain the plain password."""
    h = security.hash_password("secret123")
    assert "secret123" not in h
    assert h.startswith("scrypt$")


def test_correct_password_verifies():
    h = security.hash_password("secret123")
    assert security.verify_password("secret123", h) is True


def test_wrong_password_fails():
    h = security.hash_password("secret123")
    assert security.verify_password("Secret123", h) is False


def test_same_password_gets_different_hashes():
    """Random salt => two hashes of the same password differ, both still verify."""
    a = security.hash_password("secret123")
    b = security.hash_password("secret123")
    assert a != b
    assert security.verify_password("secret123", a)
    assert security.verify_password("secret123", b)


# ---------------------------------------------------------------------------
# JWT
# ---------------------------------------------------------------------------
def test_token_roundtrip():
    token = security.create_token("budi")
    payload = security.decode_token(token)
    assert payload["sub"] == "budi"
    assert payload["exp"] > time.time()


def test_token_has_three_parts():
    assert len(security.create_token("budi").split(".")) == 3


def test_tampered_token_is_rejected():
    """Changing the payload breaks the signature -> decode returns None."""
    header, payload, signature = security.create_token("budi").split(".")
    forged = f"{header}.{payload[:-3]}XXX.{signature}"
    assert security.decode_token(forged) is None


def test_expired_token_is_rejected():
    token = security.create_token("budi", expires_in=-1)
    assert security.decode_token(token) is None


def test_garbage_token_is_rejected():
    assert security.decode_token("not-a-token") is None
    assert security.decode_token("a.b.c") is None


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------
def test_create_user_hashes_password(tmp_path):
    users = {}
    store.create_user(users, "budi", "secret123")
    assert users["budi"]["password_hash"].startswith("scrypt$")
    assert "secret123" not in users["budi"]["password_hash"]


def test_duplicate_username_is_rejected():
    users = {}
    store.create_user(users, "budi", "secret123")
    with pytest.raises(ValueError):
        store.create_user(users, "budi", "other")


def test_load_missing_file_returns_empty(tmp_path):
    assert store.load(tmp_path / "does-not-exist.json") == {}


def test_save_then_load_roundtrip(tmp_path):
    path = tmp_path / "users.json"
    users = {}
    store.create_user(users, "budi", "secret123")
    store.save(users, path)
    assert store.load(path) == users
