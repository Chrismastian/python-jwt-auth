# python-jwt-auth

[![CI](https://github.com/Chrismastian/python-jwt-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/Chrismastian/python-jwt-auth/actions/workflows/ci.yml)

A small authentication API built with the **Python standard library only** — no
PyJWT, no Flask, no FastAPI. Every mechanism (password hashing, JWT signing,
auth middleware) is written out by hand so you can read how it actually works
under the hood.

## What it does

Three endpoints:

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/register` | Create a user. The password is hashed before it is stored. |
| `POST` | `/login` | Exchange username + password for a signed JWT. |
| `GET`  | `/me` | Protected route. Requires `Authorization: Bearer <token>`. |

## How the pieces fit

- **`auth/security.py`** — password hashing (`hashlib.scrypt` with a random
  per-user salt, compared with `hmac.compare_digest`) and JWT
  (`create_token` / `decode_token` using HMAC-SHA256).
- **`auth/store.py`** — data layer: users live in a JSON file as a
  `{username: record}` map.
- **`auth/server.py`** — HTTP layer (`http.server`). `_current_user()` is the
  auth middleware that reads the `Bearer` token and returns the username.

## Why hand-rolled JWT?

Because the point is to understand the mechanism, not to import it. A JWT is
three base64url parts joined by dots:

```
header.payload.signature
```

The header and payload are **not secret** — anyone can decode them. What keeps
the token trustworthy is the signature: an HMAC of `header.payload` computed
with a server-side secret key. Change one byte of the payload and the signature
no longer matches, so `decode_token` rejects it. For production you would use a
maintained library; here the value is seeing exactly why it is safe.

## Run it

```bash
python -m auth.server
```

Then, in another terminal:

```bash
# register
curl -X POST http://localhost:8000/register -d '{"username":"budi","password":"secret123"}'

# login -> copy the token from the response
curl -X POST http://localhost:8000/login -d '{"username":"budi","password":"secret123"}'

# protected route
curl http://localhost:8000/me -H "Authorization: Bearer <token>"
```

## Tests

```bash
pip install pytest
pytest
```

The suite covers hashing (a wrong password fails, the same password yields
different hashes), token round-trips, tampered/expired/garbage tokens, and the
full register -> login -> `/me` flow over real HTTP.

## Notes

- `SECRET_KEY` is read from the `JWT_SECRET` environment variable, falling back
  to a dev default. Set a real secret in production.
- Users are stored in `users.json`, which is git-ignored.
- A token cannot be revoked before it expires (the classic JWT revocation
  problem). Production systems pair a short-lived access token with a refresh
  token and a denylist.
