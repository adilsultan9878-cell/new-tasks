"""Research Lab API (Phase 9): datasets, rule experiments, reproduction checks.

``lab:read`` views, ``lab:run`` builds datasets and runs experiments. Nothing here changes live
detection, alerts or incidents.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import defer

from app.api.deps import DB, OrgContext, require
from app.core.errors import not_found
from app.lab import rules
from app.lab import service as lab
from app.models import LabDataset, LabExperiment, User
from app.schemas.lab import (
    DatasetDetail,
    DatasetFromEvents,
    DatasetOut,
    DatasetUpload,
    ExperimentIn,
    ExperimentOut,
    Reproduction,
)
from app.services import audit

router = APIRouter(prefix="/organizations/{org_id}/lab", tags=["research-lab"])
Read = Annotated[OrgContext, Depends(require("lab:read"))]
Run = Annotated[OrgContext, Depends(require("lab:run"))]
UPLOAD_LIMIT = 4_000_000  # 5000 rows of lab data


def _names(db: DB, ids: set[uuid.UUID | None]) -> dict[uuid.UUID, str]:
    wanted = {i for i in ids if i}
    if not wanted:
        return {}
    return {u.id: u.full_name or u.email for u in db.scalars(select(User).where(User.id.in_(wanted)))}


def _datasets_out(db: DB, org_id: uuid.UUID, rows: list[LabDataset]) -> list[DatasetOut]:
    counts = dict(
        db.execute(
            select(LabExperiment.dataset_id, func.count())
            .where(LabExperiment.organization_id == org_id)
            .group_by(LabExperiment.dataset_id)
        ).all()
    )
    names = _names(db, {r.created_by for r in rows})
    out = []
    for r in rows:
        item = DatasetOut.model_validate(r)
        item.created_by_name = names.get(r.created_by) if r.created_by else None
        item.experiments = int(counts.get(r.id, 0))
        out.append(item)
    return out


def _experiments_out(db: DB, org_id: uuid.UUID, rows: list[LabExperiment]) -> list[ExperimentOut]:
    names = _names(db, {r.created_by for r in rows})
    ds_names = dict(
        db.execute(
            select(LabDataset.id, LabDataset.name).where(
                LabDataset.organization_id == org_id,
                LabDataset.id.in_({r.dataset_id for r in rows} or {uuid.uuid4()}),
            )
        ).all()
    )
    out = []
    for r in rows:
        item = ExperimentOut.model_validate(r)
        item.created_by_name = names.get(r.created_by) if r.created_by else None
        item.dataset_name = ds_names.get(r.dataset_id)
        out.append(item)
    return out


@router.get("/datasets", response_model=list[DatasetOut])
def list_datasets(ctx: Read, db: DB) -> list[DatasetOut]:
    # Load only the summary columns: the frozen rows can be large.
    rows = db.scalars(
        select(LabDataset)
        .options(defer(LabDataset.rows))
        .where(LabDataset.organization_id == ctx.org_id)
        .order_by(LabDataset.created_at.desc())
    ).all()
    return _datasets_out(db, ctx.org_id, list(rows))


@router.post("/datasets", response_model=DatasetOut, status_code=status.HTTP_201_CREATED)
def create_dataset(body: DatasetFromEvents, ctx: Run, db: DB, request: Request) -> DatasetOut:
    ds = lab.from_events(
        db,
        request,
        org_id=ctx.org_id,
        user=ctx.user,
        name=body.name,
        description=body.description,
        days=body.days,
        include_simulated=body.include_simulated,
    )
    db.commit()
    return _datasets_out(db, ctx.org_id, [ds])[0]


@router.post(
    "/datasets/upload",
    response_model=DatasetOut,
    status_code=status.HTTP_201_CREATED,
    max_body_size=UPLOAD_LIMIT,
)
def upload_dataset(body: DatasetUpload, ctx: Run, db: DB, request: Request) -> DatasetOut:
    ds = lab.from_upload(
        db,
        request,
        org_id=ctx.org_id,
        user=ctx.user,
        name=body.name,
        description=body.description,
        rows_in=[r.model_dump() for r in body.rows],
    )
    db.commit()
    return _datasets_out(db, ctx.org_id, [ds])[0]


@router.get("/datasets/{dataset_id}", response_model=DatasetDetail)
def get_dataset(dataset_id: uuid.UUID, ctx: Read, db: DB) -> DatasetDetail:
    ds = lab.get_dataset(db, ctx.org_id, dataset_id)
    base = _datasets_out(db, ctx.org_id, [ds])[0]
    return DatasetDetail(**base.model_dump(), preview=ds.rows[-20:])


@router.delete("/datasets/{dataset_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_dataset(dataset_id: uuid.UUID, ctx: Run, db: DB, request: Request) -> None:
    ds = lab.get_dataset(db, ctx.org_id, dataset_id)
    audit.record(
        db,
        "lab.dataset_delete",
        request=request,
        actor_id=ctx.user.id,
        org_id=ctx.org_id,
        target_type="lab_dataset",
        target_id=ds.id,
        details={"name": ds.name, "sha256": ds.sha256},
    )
    db.delete(ds)  # its experiments go with it (they cannot be reproduced without it)
    db.commit()


@router.get("/experiments", response_model=list[ExperimentOut])
def list_experiments(ctx: Read, db: DB) -> list[ExperimentOut]:
    rows = db.scalars(
        select(LabExperiment)
        .where(LabExperiment.organization_id == ctx.org_id)
        .order_by(LabExperiment.created_at.desc())
        .limit(100)
    ).all()
    return _experiments_out(db, ctx.org_id, list(rows))


@router.post("/experiments", response_model=ExperimentOut, status_code=status.HTTP_201_CREATED)
def run_experiment(body: ExperimentIn, ctx: Run, db: DB, request: Request) -> ExperimentOut:
    ds = lab.get_dataset(db, ctx.org_id, body.dataset_id)
    exp = lab.run_experiment(
        db, request, org_id=ctx.org_id, user=ctx.user, dataset=ds, name=body.name, rule=body.rule
    )
    db.commit()
    return _experiments_out(db, ctx.org_id, [exp])[0]


@router.post("/experiments/{experiment_id}/reproduce", response_model=Reproduction)
def reproduce(experiment_id: uuid.UUID, ctx: Read, db: DB) -> Reproduction:
    exp = db.scalar(
        select(LabExperiment).where(
            LabExperiment.organization_id == ctx.org_id, LabExperiment.id == experiment_id
        )
    )
    if exp is None:
        raise not_found("Experiment")
    return Reproduction(**lab.reproduce(db, exp))


@router.get("/engine")
def engine(ctx: Read) -> dict[str, object]:
    return {
        "version": rules.ENGINE_VERSION,
        "fields": rules.FIELDS,
        "severities": rules.SEVERITY_ORDER,
        "baseline": rules.BASELINE.model_dump(mode="json"),
        "max_rows": lab.MAX_ROWS,
    }
