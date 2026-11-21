ORG = "/api/v1/organizations"


def nmap_xml(hosts):
    body = "".join(
        f'<host><status state="up"/><address addr="{ip}" addrtype="ipv4"/>'
        f'<hostnames><hostname name="{name}"/></hostnames><ports>'
        + "".join(
            f'<port protocol="tcp" portid="{p}"><state state="open"/><service name="{s}" product="x" version="1"/></port>'
            for p, s in ports
        )
        + "</ports></host>"
        for ip, name, ports in hosts
    )
    return f'<?xml version="1.0"?><nmaprun scanner="nmap">{body}</nmaprun>'


def test_scope_rules(account_factory):
    owner = account_factory()
    org = owner.create_org("Net Org")["organization"]["id"]
    url = f"{ORG}/{org}/network/scopes"
    assert (
        owner.post(url, json={"cidr": "10.0.0.0/8", "label": "too big"}).json()["error"]["code"]
        == "scope_too_large"
    )
    assert (
        owner.post(url, json={"cidr": "8.8.8.0/24", "label": "public"}).json()["error"]["code"]
        == "attestation_required"
    )
    ok_public = owner.post(url, json={"cidr": "81.2.69.0/24", "label": "DMZ", "attest_authorized": True})
    assert ok_public.status_code == 201 and ok_public.json()["is_private"] is False
    lab = owner.post(url, json={"cidr": "192.168.56.7/24", "label": "Lab"}).json()
    assert lab["cidr"] == "192.168.56.0/24" and lab["is_private"]
    assert owner.post(url, json={"cidr": "192.168.56.0/24", "label": "dup"}).status_code == 409
    assert owner.post(url, json={"cidr": "not-a-cidr", "label": "x"}).status_code == 422


def test_nmap_import_respects_scope_and_raises_events(account_factory):
    owner = account_factory()
    org = owner.create_org("Net Org")["organization"]["id"]
    imp = f"{ORG}/{org}/network/imports"
    xml = nmap_xml(
        [
            ("192.168.56.10", "fileserver", [(445, "microsoft-ds"), (80, "http")]),
            ("192.168.56.11", "printer", [(9100, "jetdirect")]),
            ("10.9.9.9", "not-ours", [(23, "telnet")]),
        ]
    )
    assert (
        owner.post(imp, json={"filename": "lab.xml", "content": xml}).json()["error"]["code"] == "no_scopes"
    )
    owner.post(f"{ORG}/{org}/network/scopes", json={"cidr": "192.168.56.0/24", "label": "Lab"})

    first = owner.post(imp, json={"filename": "lab.xml", "content": xml}).json()
    assert first == {
        "hosts_in_file": 3,
        "imported": 2,
        "out_of_scope": 1,
        "new_assets": 2,
        "new_services": 1,
        "events": 3,
    }
    assets = {a["ip_address"]: a for a in owner.get(f"{ORG}/{org}/network/assets").json()}
    assert set(assets) == {"192.168.56.10", "192.168.56.11"}  # out-of-scope host never stored
    assert assets["192.168.56.10"]["open_ports"] == [80, 445] and assets["192.168.56.10"]["source"] == "nmap"
    alerts = owner.get(f"{ORG}/{org}/alerts").json()
    assert any("on 192.168.56.10:445" in a["title"] and "Risky service" in a["title"] for a in alerts)

    xml2 = nmap_xml(
        [("192.168.56.10", "fileserver", [(445, "microsoft-ds"), (80, "http"), (8080, "http-proxy")])]
    )
    second = owner.post(imp, json={"filename": "lab2.xml", "content": xml2}).json()
    assert second["new_services"] == 1 and second["new_assets"] == 0
    titles = [
        e["title"] for e in owner.get(f"{ORG}/{org}/events", params={"category": "network"}).json()["items"]
    ]
    assert "New service exposed: http-proxy on 192.168.56.10:8080" in titles


def test_malicious_xml_is_rejected(account_factory):
    owner = account_factory()
    org = owner.create_org("Net Org")["organization"]["id"]
    owner.post(f"{ORG}/{org}/network/scopes", json={"cidr": "192.168.1.0/24", "label": "Lab"})
    bomb = (
        '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;">]>'
        "<nmaprun>&lol2;</nmaprun>"
    )
    for content in (bomb, "<html>nope</html>", "garbage"):
        resp = owner.post(f"{ORG}/{org}/network/imports", json={"filename": "x.xml", "content": content})
        assert resp.status_code == 422, content


def test_agent_ports_feed_the_asset_inventory(fleet):
    token = fleet.enroll()["device_token"]
    fleet.owner.post(f"{ORG}/{fleet.org_id}/network/scopes", json={"cidr": "10.20.0.0/16", "label": "Office"})
    fleet.device_post(
        token,
        "/heartbeat",
        {"agent_version": "1", "ip_address": "10.20.1.5", "telemetry": {"listening_ports": [22, 3389]}},
    )
    assets = fleet.owner.get(f"{ORG}/{fleet.org_id}/network/assets").json()
    assert assets[0]["ip_address"] == "10.20.1.5" and assets[0]["open_ports"] == [22, 3389]
    assert assets[0]["source"] == "agent" and assets[0]["in_authorized_scope"] and assets[0]["device_id"]


def test_network_rbac_and_isolation(account_factory):
    owner, viewer, other = account_factory("owner"), account_factory("viewer"), account_factory("other")
    org = owner.create_org("Net Org")["organization"]["id"]
    owner.post(f"{ORG}/{org}/members", json={"email": viewer.email, "role": "viewer"})
    owner.post(f"{ORG}/{org}/network/scopes", json={"cidr": "192.168.1.0/24", "label": "Lab"})
    assert viewer.get(f"{ORG}/{org}/network/scopes").status_code == 200
    assert (
        viewer.post(f"{ORG}/{org}/network/scopes", json={"cidr": "192.168.2.0/24", "label": "x"}).status_code
        == 403
    )
    other_org = other.create_org("Other")["organization"]["id"]
    assert other.get(f"{ORG}/{other_org}/network/scopes").json() == []
    assert other.get(f"{ORG}/{org}/network/assets").status_code == 404
