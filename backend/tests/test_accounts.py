"""Phase 10 accounts: registration policy, password reset, e-mail verification, invitations."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text

from app.core.config import get_settings
from app.services import email as mail
from tests.conftest import STRONG_PASSWORD, Account, make_client

API = "/api/v1"
NEW_PASSWORD = "Another-Strong-Passphrase-77"


@pytest.fixture
def email_on(monkeypatch):
    monkeypatch.setattr(get_settings(), "email_backend", "console")
    monkeypatch.setattr(get_settings(), "public_app_url", "https://console.example.com")
    mail.outbox.clear()
    yield mail.outbox
    mail.outbox.clear()


def _token(message: mail.Email, path: str) -> str:
    match = re.search(rf"https://console\.example\.com{path}#token=([A-Za-z0-9_-]+)", message.text)
    assert match, message.text
    return match.group(1)


def _register(email: str, **extra):
    return make_client().post(
        f"{API}/auth/register",
        json={"email": email, "password": STRONG_PASSWORD, "full_name": "New Person", **extra},
    )


# ------------------------------------------------------------------------------ policy
def test_policy_is_public_and_honest(client, monkeypatch):
    body = client.get(f"{API}/auth/policy").json()
    assert body == {
        "registration": "open",
        "first_account": True,
        "allowed_domains": [],
        "password_reset": False,
        "email_verification": False,
        "email_verification_required": False,
    }
    monkeypatch.setattr(get_settings(), "allow_registration", False)
    assert client.get(f"{API}/auth/policy").json()["registration"] == "invite_only"


def test_registration_modes(monkeypatch, client):
    s = get_settings()
    monkeypatch.setattr(s, "registration_mode", "invite_only")
    # An empty installation lets the first person in (they become the first owner)...
    assert client.get(f"{API}/auth/policy").json()["first_account"] is True
    assert _register("founder@example.com").status_code == 201
    assert client.get(f"{API}/auth/policy").json()["first_account"] is False
    # ...after that, invite-only means invite-only.
    closed = _register("walk-in@example.com")
    assert closed.status_code == 403 and closed.json()["error"]["code"] == "registration_closed"
    monkeypatch.setattr(s, "registration_mode", "domains")
    monkeypatch.setattr(s, "allowed_email_domains", ["blueteam.example"])
    assert _register("someone@gmail.example").status_code == 403
    assert _register("analyst@blueteam.example").status_code == 201
    assert _register("x@blueteam.example", invitation_token="not-a-real-invitation-token").status_code == 403


# ---------------------------------------------------------------------------- password reset
def test_password_reset_flow_is_single_use_and_ends_sessions(account_factory, email_on):
    user = account_factory("reset")
    email_on.clear()  # drop the sign-up verification mail
    old_token = user.token
    anon = make_client()
    unknown = anon.post(f"{API}/auth/password-reset/request", json={"email": "nobody@example.com"})
    known = anon.post(f"{API}/auth/password-reset/request", json={"email": user.email})
    assert (
        unknown.status_code == known.status_code == 202 and unknown.json() == known.json()
    )  # no enumeration
    assert len(email_on) == 1 and email_on[0].to == user.email
    token = _token(email_on[0], "/reset-password")

    weak = anon.post(f"{API}/auth/password-reset/confirm", json={"token": token, "password": "short"})
    assert weak.status_code == 422  # the link still works after a weak attempt
    ok = anon.post(f"{API}/auth/password-reset/confirm", json={"token": token, "password": NEW_PASSWORD})
    assert ok.status_code == 200
    again = anon.post(
        f"{API}/auth/password-reset/confirm", json={"token": token, "password": NEW_PASSWORD + "x"}
    )
    assert again.status_code == 400 and again.json()["error"]["code"] == "invalid_token"

    assert (
        make_client().get(f"{API}/auth/me", headers={"Authorization": f"Bearer {old_token}"}).status_code
        == 401
    )
    login = anon.post(f"{API}/auth/login", json={"email": user.email, "password": NEW_PASSWORD})
    assert login.status_code == 200 and login.json()["user"]["email_verified"] is True
    assert (
        anon.post(f"{API}/auth/login", json={"email": user.email, "password": STRONG_PASSWORD}).status_code
        == 401
    )


def test_newer_reset_links_cancel_older_ones_and_links_expire(account_factory, email_on, admin_engine):
    user = account_factory("reset2")
    email_on.clear()  # drop the sign-up verification mail
    anon = make_client()
    anon.post(f"{API}/auth/password-reset/request", json={"email": user.email})
    anon.post(f"{API}/auth/password-reset/request", json={"email": user.email})
    first, second = (_token(m, "/reset-password") for m in email_on)
    assert (
        anon.post(
            f"{API}/auth/password-reset/confirm", json={"token": first, "password": NEW_PASSWORD}
        ).status_code
        == 400
    )
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE email_tokens SET expires_at = :t"), {"t": datetime.now(UTC) - timedelta(minutes=1)}
        )
    assert (
        anon.post(
            f"{API}/auth/password-reset/confirm", json={"token": second, "password": NEW_PASSWORD}
        ).status_code
        == 400
    )
    with admin_engine.connect() as conn:
        stored = [r[0] for r in conn.execute(text("SELECT token_hash FROM email_tokens"))]
    assert stored and first not in stored and second not in stored  # only hashes are kept


def test_reset_requests_are_capped_per_address(account_factory, email_on):
    user = account_factory("cap")
    email_on.clear()  # drop the sign-up verification mail
    anon = make_client()
    for _ in range(get_settings().rate_limit_email_per_hour + 3):
        assert anon.post(f"{API}/auth/password-reset/request", json={"email": user.email}).status_code == 202
    assert len(email_on) == get_settings().rate_limit_email_per_hour


def test_without_email_the_features_say_so(account_factory):
    user = account_factory("noemail")
    resp = make_client().post(f"{API}/auth/password-reset/request", json={"email": user.email})
    assert resp.status_code == 503 and resp.json()["error"]["code"] == "email_disabled"
    assert user.post(f"{API}/auth/verify-email/request").status_code == 503


# ------------------------------------------------------------------------- verification
def test_verification_email_and_required_verification(email_on, monkeypatch):
    monkeypatch.setattr(get_settings(), "require_email_verification", True)
    resp = _register("verify-me@example.com")
    assert resp.status_code == 201 and resp.json()["user"]["email_verified"] is False
    headers = {"Authorization": f"Bearer {resp.json()['access_token']}"}
    blocked = make_client().post(f"{API}/organizations", json={"name": "Too Early"}, headers=headers)
    assert blocked.status_code == 403 and blocked.json()["error"]["code"] == "email_not_verified"

    token = _token(email_on[-1], "/verify-email")
    confirmed = make_client().post(f"{API}/auth/verify-email/confirm", json={"token": token})
    assert confirmed.status_code == 200 and confirmed.json()["email_verified"] is True
    assert (
        make_client().post(f"{API}/organizations", json={"name": "Now Allowed"}, headers=headers).status_code
        == 201
    )
    resend = make_client().post(f"{API}/auth/verify-email/request", headers=headers)
    assert resend.json()["message"] == "Your address is already confirmed."


# ---------------------------------------------------------------------------- invitations
def test_invitation_by_email_creates_an_account_and_membership(fleet, email_on, monkeypatch):
    monkeypatch.setattr(get_settings(), "registration_mode", "invite_only")
    org = f"{API}/organizations/{fleet.org_id}"
    created = fleet.owner.post(
        f"{org}/invitations", json={"email": "New.Analyst@Example.com", "role": "analyst"}
    )
    assert created.status_code == 201, created.text
    assert (
        created.json()["link"] is None and created.json()["invitation"]["email"] == "new.analyst@example.com"
    )
    token = _token(email_on[-1], "/invite")
    info = make_client().post(f"{API}/invitations/lookup", json={"token": token}).json()
    assert (
        info["organization_name"] == "Fleet Org"
        and info["role"] == "Security Analyst"
        and info["account_exists"] is False
    )

    assert (
        _register("someone.else@example.com", invitation_token=token).status_code == 403
    )  # bound to the address
    joined = _register("new.analyst@example.com", invitation_token=token)
    assert joined.status_code == 201 and joined.json()["user"]["email_verified"] is True
    headers = {"Authorization": f"Bearer {joined.json()['access_token']}"}
    orgs = make_client().get(f"{API}/organizations", headers=headers).json()
    assert [(m["organization"]["name"], m["role"]["key"]) for m in orgs] == [("Fleet Org", "analyst")]
    assert fleet.owner.get(f"{org}/invitations").json() == []  # accepted: no longer pending
    assert (
        make_client().post(f"{API}/invitations/lookup", json={"token": token}).status_code == 404
    )  # single use


def test_invitation_rules(fleet, account_factory, monkeypatch):
    org = f"{API}/organizations/{fleet.org_id}"
    analyst = account_factory("inv-analyst")
    fleet.owner.post(f"{org}/members", json={"email": analyst.email, "role": "admin"})
    # Without e-mail the inviter gets the link to pass on (once).
    created = fleet.owner.post(
        f"{org}/invitations", json={"email": "friend@example.com", "role": "viewer"}
    ).json()
    assert created["link"].startswith(get_settings().public_app_url) and "#token=" in created["link"]
    token = created["link"].split("#token=")[1]
    # Only the invited address can accept; existing members cannot be invited again.
    stranger = account_factory("stranger")
    wrong = stranger.post(f"{API}/invitations/accept", json={"token": token})
    assert wrong.status_code == 403 and wrong.json()["error"]["code"] == "wrong_account"
    dup = fleet.owner.post(f"{org}/invitations", json={"email": analyst.email, "role": "viewer"})
    assert dup.status_code == 409
    # An admin cannot invite an owner (no role above their own).
    assert (
        analyst.post(f"{org}/invitations", json={"email": "boss@example.com", "role": "owner"}).status_code
        == 403
    )
    # Re-inviting replaces the old link; revoking kills it.
    newer = fleet.owner.post(
        f"{org}/invitations", json={"email": "friend@example.com", "role": "viewer"}
    ).json()
    assert make_client().post(f"{API}/invitations/lookup", json={"token": token}).status_code == 404
    assert fleet.owner.delete(f"{org}/invitations/{newer['invitation']['id']}").status_code == 204
    newer_token = newer["link"].split("#token=")[1]
    assert make_client().post(f"{API}/invitations/lookup", json={"token": newer_token}).status_code == 404
    # Other tenants cannot see or revoke them.
    other = account_factory("other-owner")
    other_org = other.create_org("Other")["organization"]["id"]
    third = fleet.owner.post(
        f"{org}/invitations", json={"email": "third@example.com", "role": "viewer"}
    ).json()
    assert other.get(f"{API}/organizations/{other_org}/invitations").json() == []
    assert (
        other.delete(f"{API}/organizations/{other_org}/invitations/{third['invitation']['id']}").status_code
        == 404
    )
    assert other.get(f"{org}/invitations").status_code == 404


def test_existing_account_accepts_after_signing_in(fleet, account_factory):
    org = f"{API}/organizations/{fleet.org_id}"
    existing: Account = account_factory("existing")
    created = fleet.owner.post(f"{org}/invitations", json={"email": existing.email, "role": "analyst"}).json()
    token = created["link"].split("#token=")[1]
    assert (
        make_client().post(f"{API}/invitations/lookup", json={"token": token}).json()["account_exists"]
        is True
    )
    accepted = existing.post(f"{API}/invitations/accept", json={"token": token})
    assert accepted.status_code == 200 and accepted.json()["role"]["key"] == "analyst"
    assert existing.post(f"{API}/invitations/accept", json={"token": token}).status_code == 404
    audit = fleet.owner.get(f"{org}/audit-logs").json()
    actions = {e["action"] for e in (audit["items"] if isinstance(audit, dict) else audit)}
    assert {"member.invite", "member.invite_accept"} <= actions
    assert token not in str(audit)
