import jwt
import pytest

from app.core.config import get_settings
from tests.conftest import STRONG_PASSWORD, Account, make_client

REG = "/api/v1/auth/register"
LOGIN = "/api/v1/auth/login"
REFRESH = "/api/v1/auth/refresh"
CSRF = {"X-Requested-With": "sentinel-x"}


def test_register_returns_token_and_sets_httponly_refresh_cookie(client):
    resp = client.post(
        REG,
        json={"email": "Alice@Example.com", "password": STRONG_PASSWORD, "full_name": "  Alice   Analyst "},
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["token_type"] == "bearer" and body["expires_in"] == 15 * 60
    assert body["user"]["email"] == "alice@example.com"  # normalised
    assert body["user"]["full_name"] == "Alice Analyst"
    assert "password" not in str(body).lower().replace("password_", "")
    cookie = resp.headers["set-cookie"]
    assert "sx_refresh=" in cookie and "HttpOnly" in cookie and "Path=/api/v1/auth" in cookie


def test_register_rejects_duplicate_email(client):
    Account("dup@example.com")
    resp = client.post(REG, json={"email": "DUP@example.com", "password": STRONG_PASSWORD, "full_name": "X"})
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "email_taken"


@pytest.mark.parametrize("password", ["short", "password1234", "aaaaaaaaaaaaaaaa"])
def test_register_rejects_weak_passwords(client, password):
    resp = client.post(REG, json={"email": "weak@example.com", "password": password, "full_name": "W"})
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "weak_password"


@pytest.mark.parametrize(
    "payload",
    [
        {"email": "not-an-email", "password": STRONG_PASSWORD, "full_name": "X"},
        {"email": "a@example.com", "password": STRONG_PASSWORD, "full_name": "<script>"},
        {"email": "a@example.com", "password": STRONG_PASSWORD},
        {"email": "a@example.com", "password": "x" * 129, "full_name": "X"},
    ],
)
def test_register_validates_input(client, payload):
    resp = client.post(REG, json=payload)
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] in {"validation_error", "weak_password"}


def test_login_success_and_generic_failures(client):
    Account("bob@example.com")
    ok = client.post(LOGIN, json={"email": "bob@example.com", "password": STRONG_PASSWORD})
    assert ok.status_code == 200 and ok.json()["access_token"]

    wrong = client.post(LOGIN, json={"email": "bob@example.com", "password": "nope-nope-nope"})
    unknown = client.post(LOGIN, json={"email": "ghost@example.com", "password": STRONG_PASSWORD})
    assert wrong.status_code == unknown.status_code == 401
    # Same message either way: no user enumeration.
    assert wrong.json()["error"]["message"] == unknown.json()["error"]["message"]


def test_account_locks_after_repeated_failures(client):
    Account("lock@example.com")
    for _ in range(get_settings().max_failed_logins):
        assert (
            client.post(LOGIN, json={"email": "lock@example.com", "password": "wrong-password-1"}).status_code
            == 401
        )
    locked = client.post(LOGIN, json={"email": "lock@example.com", "password": STRONG_PASSWORD})
    assert locked.status_code == 423
    assert locked.json()["error"]["code"] == "account_locked"


def test_me_requires_valid_token(client):
    acct = Account("me@example.com", full_name="Me Myself")
    assert client.get("/api/v1/auth/me").status_code == 401
    assert client.get("/api/v1/auth/me", headers={"Authorization": "Bearer garbage"}).status_code == 401
    me = acct.get("/api/v1/auth/me")
    assert me.status_code == 200 and me.json()["full_name"] == "Me Myself"


def test_forged_tokens_are_rejected(client):
    acct = Account("forge@example.com")
    claims = jwt.decode(acct.token, options={"verify_signature": False})
    forged = jwt.encode(claims, "attacker-secret-" + "y" * 40, algorithm="HS256")
    none_alg = jwt.encode(claims, key=None, algorithm="none")
    for token in (forged, none_alg):
        assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_refresh_requires_csrf_header_and_rotates():
    acct = Account("rot@example.com")
    assert acct.client.post(REFRESH).status_code == 403  # no custom header
    old_cookie = acct.client.cookies.get("sx_refresh")
    resp = acct.client.post(REFRESH, headers=CSRF)
    assert resp.status_code == 200
    new_cookie = acct.client.cookies.get("sx_refresh")
    assert new_cookie and new_cookie != old_cookie
    assert resp.json()["access_token"] != acct.token


def test_concurrent_refresh_within_grace_window_is_allowed():
    """Two tabs refreshing with the same cookie at the same moment must not log the user out."""
    acct = Account("tabs@example.com")
    shared = acct.client.cookies.get("sx_refresh")
    tab_b = make_client()
    tab_b.cookies.set("sx_refresh", shared, path="/api/v1/auth")
    assert acct.client.post(REFRESH, headers=CSRF).status_code == 200
    assert tab_b.post(REFRESH, headers=CSRF).status_code == 200
    assert acct.client.post(REFRESH, headers=CSRF).status_code == 200


def test_refresh_token_reuse_revokes_the_whole_session_family(monkeypatch):
    monkeypatch.setattr(get_settings(), "refresh_reuse_grace_seconds", 0)
    acct = Account("reuse@example.com")
    stolen = acct.client.cookies.get("sx_refresh")
    assert acct.client.post(REFRESH, headers=CSRF).status_code == 200  # legit rotation

    attacker = make_client()
    attacker.cookies.set("sx_refresh", stolen, path="/api/v1/auth")
    replay = attacker.post(REFRESH, headers=CSRF)
    assert replay.status_code == 401

    # The legitimate user's newer token is now dead too (family revoked).
    assert acct.client.post(REFRESH, headers=CSRF).status_code == 401


def test_logout_revokes_refresh_and_access_tokens():
    acct = Account("out@example.com")
    assert acct.get("/api/v1/auth/me").status_code == 200
    assert acct.client.post("/api/v1/auth/logout", headers=CSRF).status_code == 200
    assert acct.client.post(REFRESH, headers=CSRF).status_code == 401
    assert acct.get("/api/v1/auth/me").status_code == 401


def test_change_password_signs_out_other_sessions():
    acct = Account("cp@example.com")
    other = make_client()
    other_login = other.post(LOGIN, json={"email": "cp@example.com", "password": STRONG_PASSWORD})
    other_token = other_login.json()["access_token"]

    bad = acct.post(
        "/api/v1/auth/change-password",
        json={"current_password": "not-the-password", "new_password": "Another-Strong-Pass-77"},
    )
    assert bad.status_code == 400

    ok = acct.post(
        "/api/v1/auth/change-password",
        json={"current_password": STRONG_PASSWORD, "new_password": "Another-Strong-Pass-77"},
    )
    assert ok.status_code == 200
    assert acct.get("/api/v1/auth/me").status_code == 200  # current session survives
    assert other.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {other_token}"}).status_code == 401
    relog = make_client().post(LOGIN, json={"email": "cp@example.com", "password": "Another-Strong-Pass-77"})
    assert relog.status_code == 200


def test_sessions_listing_marks_current(client):
    acct = Account("sess@example.com")
    client.post(LOGIN, json={"email": "sess@example.com", "password": STRONG_PASSWORD})
    sessions = acct.get("/api/v1/auth/sessions").json()
    assert len(sessions) == 2
    assert sum(s["current"] for s in sessions) == 1


def test_profile_update(client):
    acct = Account("prof@example.com")
    resp = acct.patch("/api/v1/auth/me", json={"full_name": "New Name"})
    assert resp.status_code == 200 and resp.json()["full_name"] == "New Name"


def test_auth_endpoints_are_rate_limited(client, monkeypatch):
    monkeypatch.setattr(get_settings(), "rate_limit_auth_per_minute", 3)
    codes = [
        client.post(LOGIN, json={"email": "rl@example.com", "password": "whatever-pass"}).status_code
        for _ in range(5)
    ]
    assert codes[:3] == [401, 401, 401]
    assert codes[3] == 429


def test_refresh_has_its_own_generous_limit(monkeypatch):
    """Page reloads must not be throttled by the strict login limit."""
    monkeypatch.setattr(get_settings(), "rate_limit_auth_per_minute", 2)
    acct = Account("reload@example.com")
    codes = [acct.client.post(REFRESH, headers=CSRF).status_code for _ in range(6)]
    assert codes == [200] * 6
