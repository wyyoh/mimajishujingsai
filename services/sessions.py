"""Local prototype operator sessions. Role TLS is separate from browser access."""
import hashlib
import hmac
import secrets
import threading
import time

from fastapi import HTTPException

from .governance import SUBJECTS
from .initialization import RUNTIME
from .storage import read, write

SESSIONS = {}
ATTEMPTS = []
SESSION_LOCK = threading.Lock()
COOKIE = "grid_operator_session"
ACCESS_PATH = RUNTIME / "operator-access.json"


def initialize_access():
    if not ACCESS_PATH.exists():
        write(ACCESS_PATH, {"scope": "Local prototype credentials; protect this file. Not enterprise identity or HSM custody.",
                            "accounts": {subject: secrets.token_urlsafe(24) for subject in SUBJECTS}}, True)
    from .management import MANAGEMENT_ROLES
    data = read(ACCESS_PATH)
    missing = set(MANAGEMENT_ROLES) - set(data['accounts'])
    if missing:
        data['accounts'].update({subject: secrets.token_urlsafe(24) for subject in missing})
        write(ACCESS_PATH, data, True)


def login(subject, password):
    now = time.monotonic()
    with SESSION_LOCK:
        ATTEMPTS[:] = [stamp for stamp in ATTEMPTS if now - stamp < 60]
        if len(ATTEMPTS) >= 10:
            raise HTTPException(429, "LOCAL_LOGIN_RATE_LIMIT")
        initialize_access()
        accounts = read(ACCESS_PATH)["accounts"]
        from .management import account_state, audit_event
        enabled, revision = account_state(subject)
        expected = accounts.get(subject, "unregistered-principal")
        if subject not in accounts or not enabled or not isinstance(password, str) or not hmac.compare_digest(password.encode(), expected.encode()):
            ATTEMPTS.append(now)
            audit_event(subject if subject in accounts else 'unknown', 'LOGIN', 'local_application', 'DENIED')
            raise HTTPException(401, "OPERATOR_CREDENTIALS_INVALID")
        audit_event(subject, 'LOGIN', 'local_application', 'ACCEPTED')
        token = secrets.token_urlsafe(32)
        SESSIONS[hashlib.sha256(token.encode()).hexdigest()] = (subject, now + 1800, revision)
        # Avoid retaining unbounded sessions when a local script repeatedly logs in.
        for key, (_, expiry, _) in list(SESSIONS.items()):
            if expiry <= now:
                SESSIONS.pop(key, None)
        return token


def principal(request, required=True):
    token = request.cookies.get(COOKIE, "")
    with SESSION_LOCK:
        entry = SESSIONS.get(hashlib.sha256(token.encode()).hexdigest()) if token else None
        if entry and entry[1] > time.monotonic():
            from .management import account_state
            enabled, revision = account_state(entry[0])
            if enabled and revision == entry[2]:
                return entry[0]
    if required:
        raise HTTPException(401, "LOCAL_OPERATOR_LOGIN_REQUIRED")
    return None


def logout(request):
    token = request.cookies.get(COOKIE, "")
    with SESSION_LOCK:
        entry = SESSIONS.pop(hashlib.sha256(token.encode()).hexdigest(), None)
    if entry:
        from .management import audit_event
        audit_event(entry[0], 'LOGOUT', 'local_application', 'COMPLETED')
