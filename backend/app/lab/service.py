"""Research Lab datasets and experiments (Phase 9).

* A **dataset** freezes a time-ordered, minimal copy of recorded events (category, type, severity,
  title, source, device, occurrence count, time) with a label derived from analyst decisions:
  an alert closed as *false positive* → ``benign``; an alert *resolved* or linked to an incident →
  ``malicious``; otherwise unlabelled. Uploaded lab data carries its own labels. The SHA-256 of the
  canonical rows is stored; the rows are never edited (a PostgreSQL trigger enforces it).
* An **experiment** evaluates a rule on a dataset and stores the result together with the
  dataset hash, the rule hash and the engine version. Re-running it must give the identical result.
* The lab never writes events, alerts or incidents: nothing here reaches production detection.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import AppError, not_found
from app.lab import rules
from app.models import Alert, LabDataset, LabExperiment, SecurityEvent, User
from app.services import audit

MAX_ROWS = 5000


def _iso(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat()


def digest(rows: list[dict[str, Any]]) -> str:
    return hashlib.sha256(rules.canonical(rows).encode()).hexdigest()


def _label_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    out = {"malicious": 0, "benign": 0, "unlabelled": 0}
    for r in rows:
        out[r.get("label") if r.get("label") in rules.LABELS else "unlabelled"] += 1
    return out


def _labels(db: Session, org_id: uuid.UUID, event_ids: list[uuid.UUID]) -> dict[uuid.UUID, str]:
    labels: dict[uuid.UUID, str] = {}
    if not event_ids:
        return labels
    for chunk_start in range(0, len(event_ids), 900):
        chunk = event_ids[chunk_start : chunk_start + 900]
        for event_id, st, incident_id in db.execute(
            select(Alert.event_id, Alert.status, Alert.incident_id).where(
                Alert.organization_id == org_id, Alert.event_id.in_(chunk)
            )
        ):
            if st == "false_positive":
                labels.setdefault(event_id, "benign")
            elif st == "resolved" or incident_id is not None:
                labels[event_id] = "malicious"  # a confirmed alert wins over a benign one
    return labels


def from_events(
    db: Session,
    request: Request,
    *,
    org_id: uuid.UUID,
    user: User,
    name: str,
    description: str | None,
    days: int,
    include_simulated: bool,
) -> LabDataset:
    since = datetime.now(UTC) - timedelta(days=days)
    filters = [SecurityEvent.organization_id == org_id, SecurityEvent.occurred_at >= since]
    if not include_simulated:
        filters.append(SecurityEvent.is_simulated.is_(False))
    events = db.scalars(
        select(SecurityEvent)
        .where(*filters)
        .order_by(SecurityEvent.occurred_at, SecurityEvent.id)
        .limit(MAX_ROWS + 1)
    ).all()
    if len(events) > MAX_ROWS:
        raise AppError(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "too_many_events",
            f"More than {MAX_ROWS} events in this window — choose fewer days",
        )
    labels = _labels(db, org_id, [e.id for e in events])
    rows = [
        {
            "id": str(e.id),
            "t": _iso(e.occurred_at),
            "category": e.category,
            "event_type": e.event_type,
            "severity": e.severity,
            "title": e.title,
            "source": e.source,
            "device": str(e.device_id) if e.device_id else "",
            "count": e.occurrence_count or 1,
            "label": labels.get(e.id),
        }
        for e in events
    ]
    return _store(
        db,
        request,
        org_id=org_id,
        user=user,
        name=name,
        description=description,
        source="events",
        params={"days": days, "include_simulated": include_simulated, "until": _iso(datetime.now(UTC))},
        rows=rows,
        includes_simulated=include_simulated and any(e.is_simulated for e in events),
    )


def from_upload(
    db: Session,
    request: Request,
    *,
    org_id: uuid.UUID,
    user: User,
    name: str,
    description: str | None,
    rows_in: list[dict[str, Any]],
) -> LabDataset:
    rows = sorted(
        (
            {
                "id": str(r.get("id") or i),
                "t": _iso(r["occurred_at"]),
                "category": r["category"],
                "event_type": r["event_type"],
                "severity": r["severity"],
                "title": r["title"],
                "source": r.get("source") or "upload",
                "device": r.get("device") or "",
                "count": r.get("count") or 1,
                "label": r.get("label"),
            }
            for i, r in enumerate(rows_in)
        ),
        key=lambda r: (r["t"], r["id"]),
    )
    return _store(
        db,
        request,
        org_id=org_id,
        user=user,
        name=name,
        description=description,
        source="upload",
        params={"rows_uploaded": len(rows)},
        rows=rows,
        includes_simulated=False,
    )


def _store(
    db: Session,
    request: Request,
    *,
    org_id: uuid.UUID,
    user: User,
    name: str,
    description: str | None,
    source: str,
    params: dict[str, Any],
    rows: list[dict[str, Any]],
    includes_simulated: bool,
) -> LabDataset:
    ds = LabDataset(
        id=uuid.uuid4(),
        organization_id=org_id,
        name=name,
        description=description,
        source=source,
        params=params,
        rows=rows,
        row_count=len(rows),
        label_counts=_label_counts(rows),
        sha256=digest(rows),
        includes_simulated=includes_simulated,
        created_by=user.id,
        created_at=datetime.now(UTC),
    )
    db.add(ds)
    db.flush()
    audit.record(
        db,
        "lab.dataset_create",
        request=request,
        actor_id=user.id,
        org_id=org_id,
        target_type="lab_dataset",
        target_id=ds.id,
        details={"name": name, "source": source, "rows": len(rows), "sha256": ds.sha256},
    )
    return ds


def get_dataset(db: Session, org_id: uuid.UUID, dataset_id: uuid.UUID) -> LabDataset:
    ds = db.scalar(
        select(LabDataset).where(LabDataset.organization_id == org_id, LabDataset.id == dataset_id)
    )
    if ds is None:
        raise not_found("Dataset")
    return ds


def run_experiment(
    db: Session,
    request: Request,
    *,
    org_id: uuid.UUID,
    user: User,
    dataset: LabDataset,
    name: str,
    rule: rules.Rule,
) -> LabExperiment:
    if digest(dataset.rows) != dataset.sha256:  # defence in depth: the trigger already forbids edits
        raise AppError(status.HTTP_409_CONFLICT, "dataset_altered", "The dataset no longer matches its hash")
    results = rules.run(rule, dataset.rows)
    exp = LabExperiment(
        id=uuid.uuid4(),
        organization_id=org_id,
        dataset_id=dataset.id,
        name=name,
        rule=rule.model_dump(mode="json"),
        rule_sha256=rule.digest(),
        dataset_sha256=dataset.sha256,
        engine_version=rules.ENGINE_VERSION,
        results=results,
        created_by=user.id,
        created_at=datetime.now(UTC),
    )
    db.add(exp)
    db.flush()
    audit.record(
        db,
        "lab.experiment_run",
        request=request,
        actor_id=user.id,
        org_id=org_id,
        target_type="lab_experiment",
        target_id=exp.id,
        details={
            "name": name,
            "dataset": str(dataset.id),
            "f1": results.get("f1"),
            "fired": results.get("fired"),
        },
    )
    return exp


def reproduce(db: Session, exp: LabExperiment) -> dict[str, Any]:
    dataset = db.get(LabDataset, exp.dataset_id)
    if dataset is None:
        raise not_found("Dataset")
    rule = rules.Rule.model_validate(exp.rule)
    checks = {
        "dataset_hash_matches": digest(dataset.rows) == exp.dataset_sha256,
        "rule_hash_matches": rule.digest() == exp.rule_sha256,
        "engine_version_matches": exp.engine_version == rules.ENGINE_VERSION,
    }
    again = rules.run(rule, dataset.rows)
    checks["results_identical"] = rules.canonical(again) == rules.canonical(exp.results)
    return {"reproduced": all(checks.values()), "checks": checks, "engine_version": rules.ENGINE_VERSION}
