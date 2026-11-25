from __future__ import annotations

from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, model_validator

T = TypeVar("T")


class APIModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class Page(APIModel, Generic[T]):
    items: list[T]
    total: int
    limit: int
    offset: int


class Message(APIModel):
    message: str


def no_nulls(*fields: str) -> Any:
    """For PATCH models: an explicit ``null`` on a required column is a 422, not a database error.

    Leaving a field out still means "unchanged"; sending ``null`` for it is refused.
    """

    def _check(cls: type[BaseModel], data: Any) -> Any:
        if isinstance(data, dict):
            bad = sorted(f for f in fields if f in data and data[f] is None)
            if bad:
                raise ValueError(f"{', '.join(bad)} cannot be null")
        return data

    return model_validator(mode="before")(classmethod(_check))  # type: ignore[arg-type]
