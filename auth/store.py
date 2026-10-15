"""User storage: a JSON file holding a {username: record} map.

Same file-I/O pattern as the earlier CLI repos, but the data is a dict keyed by
username so lookups are direct.
"""

import json
from pathlib import Path

from .security import hash_password

# The user database. Created automatically on first write.
DATA_FILE = Path("users.json")


def load(path: Path = DATA_FILE) -> dict:
    """Read users from the JSON file. Return {} when the file does not exist."""
    # A missing file is normal: it just means nobody has registered yet.
    if not path.exists():
        return {}

    return json.loads(path.read_text("utf-8"))


def save(users: dict, path: Path = DATA_FILE) -> None:
    """Write users to the JSON file."""
    # indent=2 keeps the file readable when opened in an editor.
    path.write_text(json.dumps(users, indent=2), "utf-8")


def create_user(users: dict, username: str, password: str) -> dict:
    """Add a new user. Raise ValueError if the username is already taken."""
    # This is a trust boundary (input from outside), so it must be validated.
    if username in users:
        raise ValueError("username already taken")

    # The password is hashed here; the plain text is never stored.
    users[username] = {"password_hash": hash_password(password)}
    return users[username]


def get_user(users: dict, username: str) -> dict | None:
    """Return the user's record, or None if the username is unknown."""
    # .get returns None instead of raising KeyError for a missing key.
    return users.get(username)
