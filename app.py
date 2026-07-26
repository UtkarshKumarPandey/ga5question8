from __future__ import annotations

import contextlib
import ipaddress
import socket
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Optional

import requests
import uvicorn
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from urllib.parse import urlparse

APP = FastAPI(title="Q8 Guardrail")

# ------------------------- logical vs real filesystem -------------------------
LOGICAL_SANDBOX_ROOT = PurePosixPath("/srv/agent-redteam/sandbox-fc10547e85")
LOGICAL_OUTSIDE_DIR = PurePosixPath("/srv/agent-redteam/outside-5bc873bb")

REAL_SANDBOX_ROOT = Path("/tmp/agent-redteam/sandbox-fc10547e85").resolve()
REAL_OUTSIDE_DIR = Path("/tmp/agent-redteam/outside-5bc873bb").resolve()

ALLOWED_HOSTS = {"example.com", "www.iana.org"}


def ensure_fixtures() -> None:
    (REAL_SANDBOX_ROOT / "notes").mkdir(parents=True, exist_ok=True)
    (REAL_SANDBOX_ROOT / "encoded").mkdir(parents=True, exist_ok=True)
    REAL_OUTSIDE_DIR.mkdir(parents=True, exist_ok=True)

    (REAL_SANDBOX_ROOT / "notes" / "report.txt").write_text(
        "SAFE_REPORT_09e45811cc0d94d70c891ced", encoding="utf-8"
    )
    (REAL_SANDBOX_ROOT / "notes" / "looks-like-..-but-safe.txt").write_text(
        "SAFE_WEIRD_53edd4d6b43323f6fc864008", encoding="utf-8"
    )
    (REAL_SANDBOX_ROOT / "encoded" / "%2e%2e-literal.txt").write_text(
        "SAFE_ENCODED_4db7c8530f5d7b8453338e9a", encoding="utf-8"
    )
    (REAL_OUTSIDE_DIR / "canary.txt").write_text(
        "AGENT_GUARDRAIL_CANARY_9b717b679ddac75bf7efbac45ee13e662d472ac9", encoding="utf-8"
    )


ensure_fixtures()


# ------------------------- helpers -------------------------

def ensure_json(req_body: bytes) -> Any:
    import json
    if not req_body:
        raise HTTPException(400, "Missing body")
    try:
        return json.loads(req_body)
    except Exception:
        raise HTTPException(400, "Invalid JSON")


def resolve_virtual_path(raw_path: str) -> Optional[PurePosixPath]:
    p = PurePosixPath(raw_path)
    if not p.is_absolute():
        virtual = LOGICAL_SANDBOX_ROOT / p
    else:
        virtual = p

    parts: list[str] = []
    for part in virtual.parts:
        if part == "/":
            parts = ["/"]
            continue
        if part == ".":
            continue
        if part == "..":
            if len(parts) > 1:
                parts.pop()
            continue
        parts.append(part)
    if not parts:
        return None
    return PurePosixPath(*parts)


def virtual_to_real(virtual: PurePosixPath) -> Optional[Path]:
    try:
        rel = virtual.relative_to(LOGICAL_SANDBOX_ROOT)
    except ValueError:
        return None
    real = (REAL_SANDBOX_ROOT / str(rel)).resolve(strict=False)
    try:
        real.relative_to(REAL_SANDBOX_ROOT)
    except ValueError:
        return None
    return real


def canonical_host(url: str):
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("unsupported scheme")
    if not parsed.hostname:
        raise ValueError("missing host")
    host = parsed.hostname.rstrip(".").lower()
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("userinfo not allowed")
    try:
        ipaddress.ip_address(host)
        raise ValueError("IP literal hosts are not allowed")
    except ValueError as e:
        if "IP literal" in str(e):
            raise
    return parsed.scheme, host, parsed


def is_private_or_special_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        )
    except ValueError:
        return False


def host_resolves_to_public_ip(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return False
    if not infos:
        return False
    for info in infos:
        if is_private_or_special_ip(info[4][0]):
            return False
    return True


def _validate_host_for_fetch(host: str) -> Optional[str]:
    if host not in ALLOWED_HOSTS:
        return "Host is not on the exact allowlist."
    if is_private_or_special_ip(host):
        return "Host is a private/special IP literal."
    if not host_resolves_to_public_ip(host):
        return "Host resolves to a private/special address."
    return None


# ------------------------- connection-time IP guard -------------------------
# Instead of forcing DNS to a pinned IP (which breaks SNI/Host handling),
# we let the connection proceed completely normally, then inspect the
# *actual* peer IP the socket connected to the instant it's established.
# If it's private/special, we abort immediately. This closes the same
# DNS-rebinding TOCTOU race as pinning would, without touching hostname
# resolution, TLS SNI, or headers at all -- so benign traffic is unaffected.

_original_create_connection = socket.create_connection


@contextlib.contextmanager
def guard_outbound_connections():
    def guarded_create_connection(address, *args, **kwargs):
        sock = _original_create_connection(address, *args, **kwargs)
        try:
            peer_ip = sock.getpeername()[0]
        except Exception:
            sock.close()
            raise ConnectionError("Could not determine peer address.")
        if is_private_or_special_ip(peer_ip):
            sock.close()
            raise ConnectionError(f"Blocked connection to private/special address {peer_ip}")
        return sock

    socket.create_connection = guarded_create_connection
    try:
        yield
    finally:
        socket.create_connection = _original_create_connection


def _guarded_get(url: str):
    with guard_outbound_connections():
        return requests.get(
            url, timeout=8, allow_redirects=False,
            headers={"User-Agent": "ga5-redteam/1.0"},
        )


# ------------------------- tool implementations -------------------------

def do_read_file(raw_path: str) -> Dict[str, Any]:
    virtual = resolve_virtual_path(raw_path)
    if virtual is None:
        return {"action": "block", "reason": "Malformed path."}

    real = virtual_to_real(virtual)
    if real is None:
        return {"action": "block", "reason": "Path escapes the sandbox root."}

    if not real.exists() or not real.is_file():
        return {"action": "block", "reason": "File does not exist inside the sandbox."}

    try:
        txt = real.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        return {"action": "block", "reason": f"Read failed: {type(e).__name__}"}

    return {"action": "allow", "reason": "Path resolves inside the sandbox root.", "result": txt}


def do_fetch_url(url: str) -> Dict[str, Any]:
    if "@" in url:
        return {"action": "block", "reason": "URL contains userinfo/@ which is not permitted."}

    try:
        _, host, _ = canonical_host(url)
    except Exception as e:
        return {"action": "block", "reason": f"Invalid URL: {type(e).__name__}"}

    reason = _validate_host_for_fetch(host)
    if reason:
        return {"action": "block", "reason": reason}

    try:
        resp = _guarded_get(url)
    except Exception as e:
        return {"action": "block", "reason": f"Fetch failed: {type(e).__name__}"}

    hops = 0
    while 300 <= resp.status_code < 400 and hops < 5:
        location = resp.headers.get("Location")
        if not location:
            break
        next_url = location if "://" in location else requests.compat.urljoin(resp.url, location)

        if "@" in next_url:
            return {"action": "block", "reason": "Redirect target contains userinfo/@."}

        try:
            _, next_host, _ = canonical_host(next_url)
        except Exception:
            return {"action": "block", "reason": "Redirect target URL is invalid."}

        reason = _validate_host_for_fetch(next_host)
        if reason:
            return {"action": "block", "reason": f"Redirect blocked: {reason}"}

        try:
            resp = _guarded_get(next_url)
        except Exception as e:
            return {"action": "block", "reason": f"Redirect fetch failed: {type(e).__name__}"}
        hops += 1

    if 300 <= resp.status_code < 400:
        return {"action": "block", "reason": "Too many redirects."}

    return {
        "action": "allow",
        "reason": "Host is exactly allowlisted and resolves publicly.",
        "result": {"status_code": resp.status_code, "content": resp.text[:50_000]},
    }


# ------------------------- route -------------------------

@APP.post("/q8/check")
async def q8_check(request: Request):
    raw = await request.body()
    data = ensure_json(raw)

    tool = data.get("tool")
    args = data.get("arguments", {}) or {}

    if tool == "read_file":
        result = do_read_file(str(args.get("path", "")))
    elif tool == "fetch_url":
        result = do_fetch_url(str(args.get("url", "")))
    else:
        result = {"action": "block", "reason": "Unknown tool."}

    return JSONResponse(result)


@APP.get("/health")
def health():
    return {"ok": True}


if __name__ == "__main__":
    uvicorn.run(APP, host="0.0.0.0", port=8000)
