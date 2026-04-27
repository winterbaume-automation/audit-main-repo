"""Minimal stdlib HTTP client matching the subset of ``requests`` used here.

Exists so the audit workflows can run without ``pip install requests``.

Mirrors the parts of the ``requests`` API the scripts touched: ``get``,
``post``, ``request``; ``Response.status_code``, ``.headers``, ``.text``,
``.ok``, ``.json()``; and a single ``HTTPError`` raised on connection-level
failure (DNS, refused, timeout). HTTP 4xx / 5xx are returned as a
``Response`` object, not raised - same shape as ``requests``.
"""

from __future__ import annotations

import json as _json
import urllib.error
import urllib.request
from dataclasses import dataclass
from email.message import Message
from typing import Any, Mapping, Optional


class HTTPError(Exception):
    """Connection-level failure (DNS, refused, timeout)."""


@dataclass
class Response:
    status_code: int
    headers: Mapping[str, str]  # lower-cased keys; HTTP names are case-insensitive
    text: str

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 300

    def json(self) -> Any:
        return _json.loads(self.text)


def _normalise_headers(raw: Optional[Message]) -> dict[str, str]:
    if raw is None:
        return {}
    return {k.lower(): v for k, v in raw.items()}


def request(
    method: str,
    url: str,
    *,
    headers: Optional[Mapping[str, str]] = None,
    json: Any = None,
    timeout: float = 30,
) -> Response:
    body: Optional[bytes] = None
    hdrs = dict(headers or {})
    if json is not None:
        body = _json.dumps(json).encode("utf-8")
        hdrs.setdefault("Content-Type", "application/json")

    req = urllib.request.Request(url, data=body, method=method.upper(), headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            text = resp.read().decode("utf-8", errors="replace")
            return Response(
                status_code=resp.status,
                headers=_normalise_headers(resp.headers),
                text=text,
            )
    except urllib.error.HTTPError as e:
        text = e.read().decode("utf-8", errors="replace") if e.fp is not None else ""
        return Response(
            status_code=e.code,
            headers=_normalise_headers(e.headers),
            text=text,
        )
    except urllib.error.URLError as e:
        raise HTTPError(str(e.reason)) from e
    except TimeoutError as e:
        raise HTTPError(f"timeout: {e}") from e


def get(
    url: str,
    headers: Optional[Mapping[str, str]] = None,
    *,
    timeout: float = 30,
) -> Response:
    return request("GET", url, headers=headers, timeout=timeout)


def post(
    url: str,
    headers: Optional[Mapping[str, str]] = None,
    *,
    json: Any = None,
    timeout: float = 30,
) -> Response:
    return request("POST", url, headers=headers, json=json, timeout=timeout)
