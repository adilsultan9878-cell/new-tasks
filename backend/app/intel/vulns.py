"""CVE intelligence: CISA KEV catalogue sync and on-demand NVD enrichment (cached globally)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.intel.client import request_json
from app.models import VulnerabilityRecord

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CACHE = timedelta(days=7)


def _date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def sync_kev(db: Session) -> dict[str, Any]:
    """Upsert the full CISA KEV catalogue. Returns counts and the catalogue version."""
    _, feed = request_json("GET", KEV_URL)
    items = feed.get("vulnerabilities") or []
    existing = {r.cve_id: r for r in db.scalars(select(VulnerabilityRecord))}
    added = updated = 0
    now = datetime.now(UTC)
    for item in items:
        cve = str(item.get("cveID", "")).upper()
        if not cve.startswith("CVE-"):
            continue
        rec = existing.get(cve)
        if rec is None:
            rec = VulnerabilityRecord(id=uuid.uuid4(), cve_id=cve, source="cisa_kev", references=[], cwes=[])
            db.add(rec)
            existing[cve] = rec
            added += 1
        else:
            updated += 1
        rec.title = (item.get("vulnerabilityName") or "")[:255] or None
        rec.vendor = (item.get("vendorProject") or "")[:120] or None
        rec.product = (item.get("product") or "")[:120] or None
        rec.description = rec.description or item.get("shortDescription")
        rec.in_cisa_kev = True
        rec.kev_date_added = _date(item.get("dateAdded"))
        rec.kev_due_date = _date(item.get("dueDate"))
        rec.kev_required_action = item.get("requiredAction")
        rec.known_ransomware_use = str(item.get("knownRansomwareCampaignUse", "")).lower() == "known"
        rec.cwes = list(item.get("cwes") or [])[:10]
        rec.fetched_at = rec.fetched_at or now
    db.flush()
    return {
        "catalog_version": feed.get("catalogVersion"),
        "total": len(items),
        "added": added,
        "updated": updated,
    }


def enrich_from_nvd(db: Session, cve_id: str, force: bool = False) -> VulnerabilityRecord:
    """Fetch CVSS, description and references from NVD (cached for 7 days)."""
    cve_id = cve_id.upper()
    rec = db.scalar(select(VulnerabilityRecord).where(VulnerabilityRecord.cve_id == cve_id))
    now = datetime.now(UTC)
    fetched = (
        rec.fetched_at
        if rec and rec.fetched_at and rec.fetched_at.tzinfo
        else (rec.fetched_at.replace(tzinfo=UTC) if rec and rec.fetched_at else None)
    )
    if rec and rec.cvss_score is not None and fetched and now - fetched < NVD_CACHE and not force:
        return rec
    headers = {"apiKey": get_settings().nvd_api_key} if get_settings().nvd_api_key else None
    _, body = request_json("GET", NVD_URL, params={"cveId": cve_id}, headers=headers)
    vulns = body.get("vulnerabilities") or []
    if not vulns:
        raise LookupError(f"{cve_id} is not in the National Vulnerability Database")
    cve = vulns[0]["cve"]
    if rec is None:
        rec = VulnerabilityRecord(id=uuid.uuid4(), cve_id=cve_id, source="nvd", references=[], cwes=[])
        db.add(rec)
    rec.description = next(
        (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), rec.description
    )
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            m = next((x for x in metrics[key] if x.get("type") == "Primary"), metrics[key][0])
            data = m.get("cvssData") or {}
            rec.cvss_score = data.get("baseScore")
            rec.cvss_vector = data.get("vectorString")
            rec.severity = (data.get("baseSeverity") or m.get("baseSeverity") or "").lower() or None
            break
    rec.published_at = _date(cve.get("published"))
    rec.last_modified_at = _date(cve.get("lastModified"))
    rec.references = [
        r.get("url") for r in (cve.get("references") or []) if r.get("url", "").startswith("https://")
    ][:25]
    cwes = [
        d.get("value")
        for w in cve.get("weaknesses") or []
        for d in w.get("description") or []
        if d.get("value")
    ]
    if cwes:
        rec.cwes = sorted(set(cwes))[:10]
    rec.fetched_at = now
    db.flush()
    return rec
