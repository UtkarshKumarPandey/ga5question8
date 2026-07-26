from __future__ import annotations

import ipaddress
import socket
from pathlib import Path
from typing import Any, Dict
from urllib.parse import urlparse, urlunparse

import requests
import uvicorn
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse

APP = FastAPI(title="Q8 Guardrail")

# ------------------------- fixture setup -------------------------

SANDBOX_ROOT = Path("/srv/agent-redteam/sandbox-fc10547e85").resolve()
OUTSIDE_DIR = Path("/srv/agent-redteam/outside-5bc873bb").resolve()

ALLOWED_HOSTS = {"example.com", "www.iana.org"}


def ensure_fixtures() -> None:
    (SANDBOX_ROOT / "notes").mkdir(parents=True, exist_ok=True)
    (SANDBOX_ROOT / "encoded").mkdir(parents=True, exist_ok=True)
    OUTSIDE_DIR.mkdir(parents=True, exist_ok=True)

    (SANDBOX_ROOT / "notes" / "report.txt").write_text(
        "SAFE_REPORT_09e45811cc0d94d70c891ced", encoding="utf-8"
    )
    (SANDBOX_ROOT / "notes" / "looks-like-..-but-safe.txt").write_text(
        "SAFE_WEIRD_53edd4d6b43323f6fc864008", encoding="utf-8"
    )
    (SANDBOX_ROOT / "encoded" / "%2e%2e-literal.txt").write_text(
        "SAFE_ENCODED_4db7c8530f5d7b8453338e9a", encoding="utf-8"
    )
    (OUTSIDE_DIR / "canary.txt").write_text(
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


def safe_abs_path(path: str, base: Path) -> Path:
    """Resolve a possibly-relative path against base, fully collapsing .. segments."""
    p = Path(path)
    if not p.is_absolute():
        p = (base / p).resolve(strict=False)
    else:
        p = p.resolve(strict=False)
    return p


def within_root(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except Exception:
        return False


def canonical_host(url: str):
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("unsupported scheme")
    if not parsed.hostname:
        raise ValueError("missing host")
    host = parsed.hostname.rstrip(".").lower()
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("userinfo not allowed")
    return parsed.scheme, host, urlunparse(parsed)


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
    """Resolve hostname and make sure every A/AAAA record is a public IP
    (defends against DNS-rebinding to loopback/private/metadata addresses)."""
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return False
    if not infos:
        return False
    for info in infos:
        ip_str = info[4][0]
        if is_private_or_special_ip(ip_str):
            return False
    return True


def exact_allowed_host(url: str) -> bool:
    try:
        _, host, _ = canonical_host(url)
    except Exception:
        return False
    if host not in ALLOWED_HOSTS:
        return False
    if is_private_or_special_ip(host):  # host itself is a raw IP
        return False
    if not host_resolves_to_public_ip(host):
        return False
    return True


# ------------------------- tool implementations -------------------------

def do_read_file(path: str) -> Dict[str, Any]:
    p = safe_abs_path(path, SANDBOX_ROOT)
    if not within_root(p, SANDBOX_ROOT):
        return {"action": "block", "reason": "Path escapes the sandbox root."}
    if not p.exists() or not p.is_file():
        return {"action": "block", "reason": "File does not exist inside the sandbox."}
    try:
        txt = p.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        return {"action": "block", "reason": f"Read failed: {type(e).__name__}"}
    return {"action": "allow", "reason": "Path resolves inside the sandbox root.", "result": txt}


def do_fetch_url(url: str) -> Dict[str, Any]:
    try:
        _, host, _ = canonical_host(url)
    except Exception as e:
        return {"action": "block", "reason": f"Invalid URL: {type(e).__name__}"}

    if host not in ALLOWED_HOSTS:
        return {"action": "block", "reason": "Host is not on the exact allowlist."}

    if is_private_or_special_ip(host):
        return {"action": "block", "reason": "Host is a private/special IP literal."}

    if not host_resolves_to_public_ip(host):
        return {"action": "block", "reason": "Host resolves to a private/special address."}

    try:
        resp = requests.get(
            url,
            timeout=8,
            allow_redirects=False,
            headers={"User-Agent": "ga5-redteam/1.0"},
        )
    except Exception as e:
        return {"action": "block", "reason": f"Fetch failed: {type(e).__name__}"}

    # Manually follow redirects, re-validating each hop against the allowlist.
    hops = 0
    while 300 <= resp.status_code < 400 and hops < 5:
        location = resp.headers.get("Location")
        if not location:
            break
        # Resolve relative redirects against the current URL.
        next_url = location if "://" in location else requests.compat.urljoin(resp.url, location)
        try:
            _, next_host, _ = canonical_host(next_url)
        except Exception:
            return {"action": "block", "reason": "Redirect target URL is invalid."}
        if next_host not in ALLOWED_HOSTS:
            return {"action": "block", "reason": "Redirect left the allowed host."}
        if is_private_or_special_ip(next_host) or not host_resolves_to_public_ip(next_host):
            return {"action": "block", "reason": "Redirect target resolves to a private address."}
        try:
            resp = requests.get(
                next_url, timeout=8, allow_redirects=False,
                headers={"User-Agent": "ga5-redteam/1.0"},
            )
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
