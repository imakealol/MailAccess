from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class PlatformCheck(BaseModel):
    name: str
    url: str
    category: str
    method: Literal["GET", "POST"] = "GET"
    body: dict | None = None
    headers: dict | None = None
    check_type: Literal["status", "body_contains", "body_not_contains", "json_field"]
    success_status: int = 200
    success_string: str | None = None
    failure_string: str | None = None
    json_success_path: str | None = None
    json_success_value: str | None = None
    confidence: Literal["high", "medium", "low"] = "medium"
    timeout: int = 8
    notes: str | None = None
    rate_limited_strings: list[str] = Field(default_factory=list)
    extract: dict[str, str] = Field(default_factory=dict)
    slug: str = ""
