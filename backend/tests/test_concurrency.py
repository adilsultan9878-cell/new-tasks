"""Phase 9: races found by the load test stay fixed (PostgreSQL: real concurrent transactions)."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor


def test_simultaneous_organizations_with_the_same_name(account_factory, postgres_only):
    accounts = [account_factory(f"race{i}") for i in range(8)]

    def create(account):
        return account.post("/api/v1/organizations", json={"name": "Acme Security"})

    with ThreadPoolExecutor(max_workers=8) as pool:
        responses = list(pool.map(create, accounts))
    assert [r.status_code for r in responses] == [201] * 8, [
        r.text for r in responses if r.status_code != 201
    ]
    slugs = [r.json()["organization"]["slug"] for r in responses]
    assert len(set(slugs)) == 8 and "acme-security" in slugs


def test_explicit_slug_conflict_is_a_409(account_factory):
    a, b = account_factory("slug-a"), account_factory("slug-b")
    assert a.post("/api/v1/organizations", json={"name": "Blue Team", "slug": "blue-team"}).status_code == 201
    taken = b.post("/api/v1/organizations", json={"name": "Other Blue Team", "slug": "blue-team"})
    assert taken.status_code == 409 and taken.json()["error"]["code"] == "slug_taken"
