
import csv
import functools
import hashlib
import json
import os
import sys
from datetime import datetime

sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
)

from shared.student import VARIANT_NUMBER

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
USERS_CSV_PATH = os.path.join(DATA_DIR, "users.csv")
LOG_JSON_PATH = os.path.join(DATA_DIR, "log.json")

HASH_ALGORITHM = "blake2s"
MIN_PASSWORD_LENGTH = 9
SALT = str(VARIANT_NUMBER).zfill(5)

users_to_register = (
    ("alice_sec", "Str0ngPass!123"),
    ("bob_admin", "Adm1nSecure#45"),
    ("carol_dev", "DevP@ssword99"),
    ("dave_net", "N3tworkSafe#77"),
    ("erin_ops", "Op3rationsKey!"),
    ("frank_qa", "QaTest#Secur3"),
    ("grace_it", "ItSupport@2024"),
    ("heidi_hr", "HrConfid3nt!al"),
    ("ivan_fin", "Financ3@Guard1"),
    ("judy_pm", "PmPlan#Str0ng9"),
)


class ValidationError(Exception):
    """Raised when a password does not meet the minimum requirements."""


def generate_hash(password: str, salt: str = "00000") -> str:
    """Generate a hexadecimal hash from a password and a salt.

    Raises:
        ValueError: if password or salt is empty or None.
        ValidationError: if the password is shorter than the
            minimum required length.
    """
    if not password or not salt:
        raise ValueError("Password and salt must not be empty.")

    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            f"Password must be at least {MIN_PASSWORD_LENGTH} "
            f"characters long."
        )

    hasher = hashlib.new(HASH_ALGORITHM)
    hasher.update((password + salt).encode("utf-8"))
    return hasher.hexdigest()


def create_user(username, password):
    """Create a (username, hash) pair for a single user."""
    hash_value = generate_hash(password, SALT)
    return username, hash_value


def create_users(users_list):
    """Create the CSV user database from a list of (login, password)."""
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(USERS_CSV_PATH, "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        for username, password in users_list:
            try:
                username, hash_value = create_user(username, password)
                writer.writerow([username, hash_value])
            except (ValueError, ValidationError) as error:
                print(f"Skipping user '{username}': {error}")


def read_users_db():
    """Read the CSV user database into a list of (login, hash) pairs."""
    users_db = []
    with open(USERS_CSV_PATH, "r", newline="", encoding="utf-8") as file:
        reader = csv.reader(file)
        for row in reader:
            if row:
                users_db.append((row[0], row[1]))
    return users_db


def print_users_table(users_db):
    """Print the user database as a formatted table."""
    print(f"{'Username':<15}{'Password hash':<70}")
    print("-" * 85)
    for username, hash_value in users_db:
        print(f"{username:<15}{hash_value:<70}")


def _append_log_entry(entry):
    """Append a single event entry to the JSON log file."""
    os.makedirs(DATA_DIR, exist_ok=True)
    try:
        with open(LOG_JSON_PATH, "r", encoding="utf-8") as file:
            events = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        events = []

    events.append(entry)

    with open(LOG_JSON_PATH, "w", encoding="utf-8") as file:
        json.dump(events, file, indent=2, ensure_ascii=False)


def log_event(func):
    """Decorator that logs every login attempt to log.json."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        result = False
        try:
            result = func(*args, **kwargs)
            return result
        finally:
            username = args[0] if args else kwargs.get("username", "")
            entry = {
                "event": "login",
                "user": username,
                "result": "success" if result else "failure",
                "timestamp": datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "args": list(args),
                "kwargs": kwargs,
            }
            _append_log_entry(entry)

    return wrapper


@log_event
def login(username: str, password: str) -> bool:
    """Authenticate a user against the stored CSV database."""
    if not username or not password:
        raise ValueError("Username and password must not be empty.")

    users_db = dict(read_users_db())
    if username not in users_db:
        return False

    return users_db[username] == generate_hash(password, SALT)


def main():
    """Run the registration, storage and login demonstration."""
    try:
        create_users(users_to_register)
        users_db = read_users_db()
        print_users_table(users_db)

        print()
        print("Login attempts:")
        test_cases = [
            ("alice_sec", "Str0ngPass!123"),
            ("bob_admin", "WrongPassword"),
            ("unknown_user", "SomePassword1"),
        ]
        for username, password in test_cases:
            try:
                success = login(username, password)
                status = "SUCCESS" if success else "FAILURE"
                print(f"  {username}: {status}")
            except (ValueError, ValidationError) as error:
                print(f"  {username}: ERROR - {error}")

    except FileNotFoundError as error:
        print(f"File not found: {error}")
    except PermissionError as error:
        print(f"Permission denied: {error}")
    except IOError as error:
        print(f"I/O error: {error}")


if __name__ == "__main__":
    main()