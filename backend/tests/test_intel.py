from datetime import UTC, datetime, timedelta

import pytest

from app.core.config import get_settings
from app.intel.client import IntelUnavailable, request_json
from app.intel.lookalike import check_host

ORG = "/api/v1/organizations"


def investigate(acct, org_id, subject_type, subject):
    return acct.post(
        f"{ORG}/{org_id}/investigations", json={"subject_type": subject_type, "subject": subject}
    )


@pytest.fixture
def keys(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "abusech_auth_key", "test-abusech")
    monkeypatch.setattr(s, "abuseipdb_api_key", "test-abuseipdb")
    monkeypatch.setattr(s, "virustotal_api_key", "")


def rdap_bootstrap(intel_mock, created: datetime):
    intel_mock.on(
        "data.iana.org",
        "/rdap/dns.json",
        {"services": [[["com", "net"], ["https://rdap.verisign.com/com/v1/"]]]},
    )
    intel_mock.on(
        "rdap.verisign.com",
        "/com/v1/domain/",
        {
            "events": [
                {"eventAction": "registration", "eventDate": created.isoformat().replace("+00:00", "Z")}
            ],
            "entities": [
                {"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]]}
            ],
        },
    )


@pytest.mark.parametrize(
    "host,brand",
    [
        ("paypa1.com", "paypal"),
        ("micros0ft-support.com", "microsoft"),
        ("xn--pypal-4ve.com", "paypal"),
        ("secure-hbl-login.top", "hbl"),
        ("jazzcash-reward.com", "jazzcash"),
        ("easypaisa.com.pk.verify-now.xyz", "easypaisa"),
    ],
)
def test_lookalike_detection(host, brand):
    assert brand in {m["brand"] for m in check_host(host)}


@pytest.mark.parametrize(
    "host", ["paypal.com", "www.paypal.com", "google.com.pk", "jazzcash.com.pk", "example.org"]
)
def test_official_and_unrelated_domains_are_not_flagged(host):
    assert check_host(host) == []


def test_ssrf_guard_only_allows_intel_hosts():
    for url in (
        "https://169.254.169.254/latest/meta-data",
        "https://internal.example/",
        "http://www.cisa.gov/x",
    ):
        with pytest.raises(IntelUnavailable):
            request_json("GET", url)


def test_url_heuristics_without_any_keys_are_honest(account_factory, intel_mock):
    owner = account_factory()
    org = owner.create_org("Intel Org")["organization"]["id"]
    rdap_bootstrap(intel_mock, datetime.now(UTC) - timedelta(days=3))
    intel_mock.on("cloudflare-dns.com", "/dns-query", {"Status": 0, "Answer": [{"data": "203.0.113.9"}]})
    resp = investigate(owner, org, "url", "http://paypa1-secure.com/account/verify?session=1")
    assert resp.status_code == 201, resp.text
    inv = resp.json()
    codes = {f["code"] for f in inv["verified_findings"]}
    assert {"brand_in_domain", "no_tls", "keywords", "new_domain"} <= codes
    assert inv["verdict"] == "malicious" and inv["risk_score"] >= 70
    checks = {c["source"]: c["status"] for c in inv["details"]["checks"]}
    assert checks["urlhaus"] == "not_configured" and checks["rdap"] == "ok"
    assert "Not configured: urlhaus" in inv["summary"]
    # The suspicious URL itself was never requested — only registries/DNS were asked about it.
    assert not any("paypa1-secure.com/account" in c for c in intel_mock.calls)
    assert all(c.startswith("https://") for c in intel_mock.calls)


def test_urlhaus_listing_makes_it_malicious_and_raises_an_alert(account_factory, intel_mock, keys):
    owner = account_factory()
    org = owner.create_org("Intel Org")["organization"]["id"]
    intel_mock.on(
        "urlhaus-api.abuse.ch",
        "/v1/url/",
        lambda req: (
            {
                "query_status": "ok",
                "threat": "malware_download",
                "url_status": "online",
                "tags": ["emotet"],
                "date_added": "2026-11-01",
                "urlhaus_reference": "https://urlhaus.abuse.ch/url/1/",
            }
            if req.headers.get("Auth-Key") == "test-abusech"
            else {"query_status": "unknown_auth_key"}
        ),
    )
    inv = investigate(owner, org, "url", "https://203.0.113.7/payload.pdf.exe").json()
    assert inv["verdict"] == "malicious" and inv["risk_score"] >= 85
    intel = [f for f in inv["verified_findings"] if f["kind"] == "intel"]
    assert intel[0]["source"] == "urlhaus" and "emotet" in intel[0]["detail"]
    assert {"executable_download", "ip_host"} <= {f["code"] for f in inv["verified_findings"]}

    alerts = owner.get(f"{ORG}/{org}/alerts").json()
    assert alerts and alerts[0]["severity"] == "high"
    indicators = owner.get(f"{ORG}/{org}/indicators", params={"verdict": "malicious"}).json()["items"]
    assert {i["indicator_type"] for i in indicators} >= {"url", "ipv4"}
    assert all(i["is_verified"] for i in indicators)
    assert owner.get(f"{ORG}/{org}/investigations", params={"subject_type": "url,email"}).json()["total"] == 1
    assert owner.get(f"{ORG}/{org}/investigations", params={"subject_type": "hash"}).json()["total"] == 0
    listed = owner.get(f"{ORG}/{org}/investigations").json()
    assert (
        listed["total"] == 1 and owner.get(f"{ORG}/{org}/dashboard/summary").json()["recent_investigations"]
    )


def test_ip_investigations(account_factory, intel_mock, keys):
    owner = account_factory()
    org = owner.create_org("Intel Org")["organization"]["id"]
    private = investigate(owner, org, "ip", "192.168.1.10").json()
    assert private["verdict"] == "unknown" and private["verified_findings"][0]["code"] == "non_public"
    assert not intel_mock.calls  # no external lookup for private addresses

    intel_mock.on(
        "api.abuseipdb.com",
        "/api/v2/check",
        {"data": {"abuseConfidenceScore": 93, "totalReports": 412, "countryCode": "NL", "isp": "Bad ISP"}},
    )
    bad = investigate(owner, org, "ip", "185.220.101.4").json()
    assert bad["verdict"] == "malicious" and bad["details"]["abuseipdb"]["totalReports"] == 412
    assert investigate(owner, org, "ip", "999.1.1.1").status_code == 422


def test_hash_investigations(account_factory, intel_mock, keys):
    owner = account_factory()
    org = owner.create_org("Intel Org")["organization"]["id"]
    assert investigate(owner, org, "hash", "not-a-hash").status_code == 422
    sha = "a" * 64
    intel_mock.on(
        "mb-api.abuse.ch",
        "/api/v1/",
        {
            "query_status": "ok",
            "data": [
                {
                    "signature": "AgentTesla",
                    "file_type": "exe",
                    "first_seen": "2026-10-01",
                    "tags": ["stealer"],
                    "sha256_hash": sha,
                }
            ],
        },
    )
    inv = investigate(owner, org, "hash", sha.upper()).json()
    assert inv["subject"] == sha and inv["verdict"] == "malicious"
    assert "AgentTesla" in inv["verified_findings"][0]["title"]


def test_hash_without_sources_is_unknown_not_clean(account_factory):
    owner = account_factory()
    org = owner.create_org("Intel Org")["organization"]["id"]
    inv = investigate(owner, org, "hash", "b" * 64).json()
    assert inv["verdict"] == "unknown"
    assert "Absence of findings is not proof of safety" in inv["summary"]


EMAIL = """Received: from mail.evil.example (203.0.113.5) by mx.example.org
Authentication-Results: mx.example.org; spf=fail smtp.mailfrom=evil.example; dkim=none; dmarc=fail header.from=paypa1.com
From: "PayPal Security" <service@paypa1.com>
Reply-To: billing@collector.example
Return-Path: <bounce@evil.example>
Subject: URGENT: your account is suspended - verify now
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="b1"

--b1
Content-Type: text/plain

Log in here: http://198.51.100.4/paypal/login.php to restore access.
--b1
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="invoice.pdf.exe"

AAAA
--b1--
"""


def test_email_header_analysis(account_factory):
    owner = account_factory()
    org = owner.create_org("Intel Org")["organization"]["id"]
    inv = investigate(owner, org, "email", EMAIL).json()
    codes = {f["code"] for f in inv["verified_findings"]}
    assert {
        "spf_fail",
        "dmarc_fail",
        "reply_to_mismatch",
        "display_brand",
        "sender_lookalike",
        "risky_attachment",
        "urgency",
        "link0_ip_host",
    } <= codes
    assert inv["verdict"] == "malicious"
    assert inv["details"]["email"]["authentication"] == {"spf": "fail", "dkim": "none", "dmarc": "fail"}
    assert investigate(owner, org, "email", "just some text").status_code == 422


def test_watchlist_match(account_factory):
    owner = account_factory()
    org = owner.create_org("Intel Org")["organization"]["id"]
    added = owner.post(
        f"{ORG}/{org}/indicators",
        json={
            "indicator_type": "domain",
            "value": "Evil-Corp.example",
            "verdict": "malicious",
            "note": "phishing kit seen in Oct",
        },
    )
    assert added.status_code == 201
    inv = investigate(owner, org, "domain", "evil-corp.example").json()
    watch = [f for f in inv["verified_findings"] if f["code"] == "watchlist"]
    assert watch and "phishing kit" in watch[0]["detail"] and inv["verdict"] == "malicious"
    # Investigations never override an analyst's verdict.
    row = owner.get(f"{ORG}/{org}/indicators", params={"source": "analyst"}).json()["items"][0]
    assert row["verdict"] == "malicious" and row["confidence"] == 100


def test_intel_rbac_and_tenant_isolation(account_factory):
    owner, viewer, other = account_factory("owner"), account_factory("viewer"), account_factory("other")
    org = owner.create_org("Intel Org")["organization"]["id"]
    owner.post(f"{ORG}/{org}/members", json={"email": viewer.email, "role": "viewer"})
    inv = investigate(owner, org, "domain", "example.com").json()
    assert investigate(viewer, org, "domain", "example.com").status_code == 403
    assert viewer.get(f"{ORG}/{org}/investigations/{inv['id']}").status_code == 200
    assert (
        viewer.post(
            f"{ORG}/{org}/indicators", json={"indicator_type": "domain", "value": "x.example"}
        ).status_code
        == 403
    )
    other_org = other.create_org("Other")["organization"]["id"]
    assert other.get(f"{ORG}/{other_org}/investigations/{inv['id']}").status_code == 404
    assert other.get(f"{ORG}/{other_org}/indicators").json()["total"] == 0
    assert other.get(f"{ORG}/{org}/investigations").status_code == 404


def test_providers_report_configuration(account_factory, keys):
    acct = account_factory()
    providers = {p["key"]: p for p in acct.get("/api/v1/intel/providers").json()}
    assert providers["urlhaus"]["configured"] and providers["abuseipdb"]["configured"]
    assert (
        not providers["virustotal"]["configured"]
        and providers["virustotal"]["requires_key"] == "VIRUSTOTAL_API_KEY"
    )
    assert providers["rdap"]["configured"] and providers["cisa_kev"]["configured"]


KEV_FEED = {
    "catalogVersion": "2026.11.20",
    "count": 2,
    "vulnerabilities": [
        {
            "cveID": "CVE-2021-44228",
            "vendorProject": "Apache",
            "product": "Log4j2",
            "vulnerabilityName": "Apache Log4j2 RCE",
            "dateAdded": "2021-12-10",
            "shortDescription": "JNDI injection",
            "requiredAction": "Apply updates",
            "dueDate": "2021-12-24",
            "knownRansomwareCampaignUse": "Known",
            "cwes": ["CWE-917"],
        },
        {
            "cveID": "CVE-2023-4966",
            "vendorProject": "Citrix",
            "product": "NetScaler",
            "vulnerabilityName": "Citrix Bleed",
            "dateAdded": "2023-10-18",
            "shortDescription": "Info disclosure",
            "requiredAction": "Patch",
            "dueDate": "2023-11-08",
            "knownRansomwareCampaignUse": "Unknown",
            "cwes": [],
        },
    ],
}
NVD = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-44228",
                "published": "2021-12-10T10:15:09.143",
                "lastModified": "2025-02-04T15:15:13.773",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP.",
                    }
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "type": "Primary",
                            "cvssData": {
                                "baseScore": 10.0,
                                "baseSeverity": "CRITICAL",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                            },
                        }
                    ]
                },
                "references": [
                    {"url": "https://logging.apache.org/log4j/2.x/security.html"},
                    {"url": "http://insecure.example"},
                ],
                "weaknesses": [{"description": [{"value": "CWE-502"}]}],
            }
        }
    ]
}


def test_kev_sync_search_and_nvd_enrichment(account_factory, intel_mock):
    from app.api.v1.routes.intel import reset_kev_throttle

    reset_kev_throttle()
    owner, viewer = account_factory("owner"), account_factory("viewer")
    org = owner.create_org("Vuln Org")["organization"]["id"]
    owner.post(f"{ORG}/{org}/members", json={"email": viewer.email, "role": "viewer"})
    intel_mock.on("www.cisa.gov", "/sites/default/files/feeds/", KEV_FEED)
    intel_mock.on(
        "services.nvd.nist.gov",
        "/rest/json/cves/2.0",
        lambda req: NVD if req.url.params.get("cveId") == "CVE-2021-44228" else {"vulnerabilities": []},
    )

    assert viewer.post(f"{ORG}/{org}/vulnerabilities/sync-kev").status_code == 403
    result = owner.post(f"{ORG}/{org}/vulnerabilities/sync-kev").json()
    assert result == {"catalog_version": "2026.11.20", "total": 2, "added": 2, "updated": 0}
    assert owner.post(f"{ORG}/{org}/vulnerabilities/sync-kev").status_code == 429  # throttled

    stats = viewer.get("/api/v1/vulnerabilities/stats").json()
    assert stats["kev_total"] == 2 and stats["ransomware_total"] == 1
    found = viewer.get("/api/v1/vulnerabilities", params={"q": "citrix"}).json()
    assert [v["cve_id"] for v in found["items"]] == ["CVE-2023-4966"]
    assert viewer.get("/api/v1/vulnerabilities", params={"ransomware_only": True}).json()["total"] == 1

    detail = viewer.get("/api/v1/vulnerabilities/CVE-2021-44228").json()
    assert detail["cvss_score"] == 10.0 and detail["severity"] == "critical" and detail["in_cisa_kev"]
    assert detail["references"] == ["https://logging.apache.org/log4j/2.x/security.html"]  # https only
    calls = len(intel_mock.calls)
    viewer.get("/api/v1/vulnerabilities/CVE-2021-44228")
    assert len(intel_mock.calls) == calls  # served from cache
    assert viewer.get("/api/v1/vulnerabilities/not-a-cve").status_code == 422
    reserved = investigate(owner, org, "ip", "198.51.100.23").json()
    assert reserved["verified_findings"][0]["title"] == "Reserved address"
    assert viewer.get("/api/v1/vulnerabilities/CVE-1999-0001").status_code == 404


def test_unregistered_domain_is_reported(account_factory, intel_mock):
    owner = account_factory()
    org = owner.create_org("Intel Org")["organization"]["id"]
    intel_mock.on(
        "data.iana.org", "/rdap/dns.json", {"services": [[["com"], ["https://rdap.verisign.com/com/v1/"]]]}
    )
    intel_mock.on("rdap.verisign.com", "/com/v1/domain/", {"errorCode": 404}, status=404)
    intel_mock.on("cloudflare-dns.com", "/dns-query", {"Status": 3})
    inv = investigate(owner, org, "domain", "hbl-secure-verify-login.com").json()
    codes = {f["code"] for f in inv["verified_findings"]}
    assert {"not_registered", "nxdomain", "brand_in_domain"} <= codes
    assert {c["source"]: c["status"] for c in inv["details"]["checks"]}["rdap"] == "ok"
