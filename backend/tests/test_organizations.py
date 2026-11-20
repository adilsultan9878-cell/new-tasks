from sqlalchemy import text

from app.rbac.catalog import PERMISSIONS, ROLES

ORGS = "/api/v1/organizations"


def test_create_organization_makes_creator_owner(account_factory):
    owner = account_factory("owner")
    body = owner.create_org(
        "Karachi Cyber Research Lab", industry="research", description="University SOC lab"
    )
    assert body["organization"]["slug"] == "karachi-cyber-research-lab"
    assert body["role"]["key"] == "owner"
    assert set(body["permissions"]) == set(PERMISSIONS)
    assert body["member_count"] == 1

    listed = owner.get(ORGS).json()
    assert [m["organization"]["id"] for m in listed] == [body["organization"]["id"]]


def test_slug_rules(account_factory):
    owner = account_factory()
    owner.create_org("First", slug="blue-team")
    dup = owner.post(ORGS, json={"name": "Second", "slug": "blue-team"})
    assert dup.status_code == 409
    bad = owner.post(ORGS, json={"name": "Third", "slug": "Bad Slug!"})
    assert bad.status_code == 422
    auto1 = owner.create_org("Same Name")
    auto2 = owner.create_org("Same Name")
    assert auto1["organization"]["slug"] != auto2["organization"]["slug"]


def test_create_organization_validation(account_factory):
    owner = account_factory()
    assert owner.post(ORGS, json={"name": "x"}).status_code == 422
    assert owner.post(ORGS, json={"name": "Valid", "industry": "piracy"}).status_code == 422
    assert owner.post(ORGS, json={}).status_code == 422


def test_owner_can_update_organization_and_it_is_audited(account_factory):
    owner = account_factory()
    org_id = owner.create_org("Old Name")["organization"]["id"]
    resp = owner.patch(f"{ORGS}/{org_id}", json={"name": "New Name", "industry": "education"})
    assert resp.status_code == 200
    assert resp.json()["organization"]["name"] == "New Name"
    logs = owner.get(f"{ORGS}/{org_id}/audit-logs").json()
    actions = [i["action"] for i in logs["items"]]
    assert actions[:2] == ["org.update", "org.create"]
    assert logs["items"][0]["actor"]["email"] == owner.email


def _add(owner, org_id, email, role):
    return owner.post(f"{ORGS}/{org_id}/members", json={"email": email, "role": role})


def test_add_member_and_notify(account_factory):
    owner, analyst = account_factory("owner"), account_factory("analyst")
    org_id = owner.create_org("Team")["organization"]["id"]
    resp = _add(owner, org_id, analyst.email, "analyst")
    assert resp.status_code == 201
    assert resp.json()["role"]["key"] == "analyst"

    notes = analyst.get("/api/v1/notifications").json()
    assert notes["unread"] == 1 and "Team" in notes["items"][0]["title"]
    nid = notes["items"][0]["id"]
    assert analyst.post(f"/api/v1/notifications/{nid}/read").status_code == 200
    assert analyst.get("/api/v1/notifications").json()["unread"] == 0
    # Another user cannot touch someone else's notification.
    assert owner.post(f"/api/v1/notifications/{nid}/read").status_code == 404

    orgs = analyst.get(ORGS).json()
    assert orgs[0]["role"]["key"] == "analyst"
    assert "members:manage" not in orgs[0]["permissions"]
    assert set(orgs[0]["permissions"]) == set(ROLES["analyst"]["permissions"])

    assert _add(owner, org_id, analyst.email, "viewer").status_code == 409
    assert _add(owner, org_id, "nobody@example.com", "viewer").status_code == 404
    assert _add(owner, org_id, analyst.email, "superuser").status_code == 400


def test_rbac_enforcement(account_factory):
    owner, admin, analyst, viewer, outsider = (
        account_factory(p) for p in ("owner", "admin", "analyst", "viewer", "outsider")
    )
    org_id = owner.create_org("RBAC Org")["organization"]["id"]
    for acct, role in ((admin, "admin"), (analyst, "analyst"), (viewer, "viewer")):
        assert _add(owner, org_id, acct.email, role).status_code == 201

    # Viewer: read-only.
    assert viewer.get(f"{ORGS}/{org_id}/dashboard/summary").status_code == 200
    assert viewer.patch(f"{ORGS}/{org_id}", json={"name": "Hacked"}).status_code == 403
    assert viewer.get(f"{ORGS}/{org_id}/audit-logs").status_code == 200
    # Analyst: cannot manage members.
    assert _add(analyst, org_id, outsider.email, "viewer").status_code == 403
    # Admin: can manage members but cannot mint owners.
    assert _add(admin, org_id, outsider.email, "owner").status_code == 403
    assert _add(admin, org_id, outsider.email, "viewer").status_code == 201

    members = {m["email"]: m for m in owner.get(f"{ORGS}/{org_id}/members").json()}
    owner_member_id = members[owner.email]["id"]
    # Admin cannot demote or remove the (more privileged) owner.
    assert (
        admin.patch(f"{ORGS}/{org_id}/members/{owner_member_id}", json={"role": "viewer"}).status_code == 403
    )
    assert admin.delete(f"{ORGS}/{org_id}/members/{owner_member_id}").status_code == 403
    # Denials are recorded in the audit trail.
    denied = owner.get(f"{ORGS}/{org_id}/audit-logs", params={"outcome": "denied"}).json()
    assert denied["total"] >= 2


def test_last_owner_is_protected_and_members_can_leave(account_factory):
    owner, viewer = account_factory("owner"), account_factory("viewer")
    org_id = owner.create_org("Solo")["organization"]["id"]
    _add(owner, org_id, viewer.email, "viewer")
    members = {m["email"]: m["id"] for m in owner.get(f"{ORGS}/{org_id}/members").json()}

    demote = owner.patch(f"{ORGS}/{org_id}/members/{members[owner.email]}", json={"role": "admin"})
    assert demote.status_code == 400 and demote.json()["error"]["code"] == "last_owner"
    assert owner.delete(f"{ORGS}/{org_id}/members/{members[owner.email]}").status_code == 400

    # A viewer cannot remove others, but can leave.
    assert viewer.delete(f"{ORGS}/{org_id}/members/{members[owner.email]}").status_code == 403
    assert viewer.delete(f"{ORGS}/{org_id}/members/{members[viewer.email]}").status_code == 204
    assert viewer.get(f"{ORGS}/{org_id}").status_code == 404

    # Promote someone else to owner, then the original owner may step down.
    _add(owner, org_id, viewer.email, "admin")
    members = {m["email"]: m["id"] for m in owner.get(f"{ORGS}/{org_id}/members").json()}
    assert (
        owner.patch(f"{ORGS}/{org_id}/members/{members[viewer.email]}", json={"role": "owner"}).status_code
        == 200
    )
    assert (
        owner.patch(f"{ORGS}/{org_id}/members/{members[owner.email]}", json={"role": "viewer"}).status_code
        == 200
    )


def test_roles_endpoint_matches_catalog(account_factory):
    acct = account_factory()
    roles = {r["key"]: r for r in acct.get(f"{ORGS}/roles").json()}
    assert set(roles) == set(ROLES)
    for key, spec in ROLES.items():
        assert set(roles[key]["permissions"]) == set(spec["permissions"]), key


def test_seeded_rbac_matches_catalog(admin_engine):
    """The migration seeds a frozen snapshot; this catches drift from app/rbac/catalog.py."""
    with admin_engine.connect() as conn:
        perms = set(conn.scalars(text("SELECT key FROM permissions")))
    assert perms == set(PERMISSIONS)
