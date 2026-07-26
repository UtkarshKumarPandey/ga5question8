# from __future__ import annotations

# import ipaddress
# import socket
# from pathlib import Path, PurePosixPath
# from typing import Any, Dict
# from urllib.parse import urlparse

# import requests
# import uvicorn
# from fastapi import FastAPI, Request, HTTPException
# from fastapi.responses import JSONResponse

# APP = FastAPI(title="Q8 Guardrail")

# # ------------------------- logical vs real filesystem -------------------------
# # The grader references this "logical" absolute path in its requests/spec.
# LOGICAL_SANDBOX_ROOT = PurePosixPath("/srv/agent-redteam/sandbox-fc10547e85")
# LOGICAL_OUTSIDE_DIR = PurePosixPath("/srv/agent-redteam/outside-5bc873bb")

# # Where we actually store the bytes on disk (writable on Render's free tier).
# REAL_SANDBOX_ROOT = Path("/tmp/agent-redteam/sandbox-fc10547e85").resolve()
# REAL_OUTSIDE_DIR = Path("/tmp/agent-redteam/outside-5bc873bb").resolve()

# ALLOWED_HOSTS = {"example.com", "www.iana.org"}


# def ensure_fixtures() -> None:
#     (REAL_SANDBOX_ROOT / "notes").mkdir(parents=True, exist_ok=True)
#     (REAL_SANDBOX_ROOT / "encoded").mkdir(parents=True, exist_ok=True)
#     REAL_OUTSIDE_DIR.mkdir(parents=True, exist_ok=True)

#     (REAL_SANDBOX_ROOT / "notes" / "report.txt").write_text(
#         "SAFE_REPORT_09e45811cc0d94d70c891ced", encoding="utf-8"
#     )
#     (REAL_SANDBOX_ROOT / "notes" / "looks-like-..-but-safe.txt").write_text(
#         "SAFE_WEIRD_53edd4d6b43323f6fc864008", encoding="utf-8"
#     )
#     (REAL_SANDBOX_ROOT / "encoded" / "%2e%2e-literal.txt").write_text(
#         "SAFE_ENCODED_4db7c8530f5d7b8453338e9a", encoding="utf-8"
#     )
#     (REAL_OUTSIDE_DIR / "canary.txt").write_text(
#         "AGENT_GUARDRAIL_CANARY_9b717b679ddac75bf7efbac45ee13e662d472ac9", encoding="utf-8"
#     )


# ensure_fixtures()


# # ------------------------- helpers -------------------------

# def ensure_json(req_body: bytes) -> Any:
#     import json
#     if not req_body:
#         raise HTTPException(400, "Missing body")
#     try:
#         return json.loads(req_body)
#     except Exception:
#         raise HTTPException(400, "Invalid JSON")


# def resolve_virtual_path(raw_path: str) -> PurePosixPath | None:
#     """
#     Interpret raw_path the way the grader intends it (relative to, or under,
#     the logical sandbox root), fully collapse '..' segments in POSIX terms,
#     and return the resulting *virtual* absolute path -- or None if it's not
#     a well-formed path at all.
#     """
#     p = PurePosixPath(raw_path)
#     if not p.is_absolute():
#         virtual = LOGICAL_SANDBOX_ROOT / p
#     else:
#         virtual = p

#     # Manually collapse '.' and '..' components (PurePosixPath doesn't do this).
#     parts: list[str] = []
#     for part in virtual.parts:
#         if part == "/":
#             parts = ["/"]
#             continue
#         if part == ".":
#             continue
#         if part == "..":
#             if len(parts) > 1:
#                 parts.pop()
#             continue
#         parts.append(part)
#     if not parts:
#         return None
#     normalized = PurePosixPath(*parts)
#     return normalized


# def virtual_to_real(virtual: PurePosixPath) -> Path | None:
#     """Map a normalized virtual path under the logical sandbox root to the
#     real writable path on disk. Returns None if it doesn't map anywhere we
#     actually serve content from (i.e. outside sandbox)."""
#     try:
#         rel = virtual.relative_to(LOGICAL_SANDBOX_ROOT)
#     except ValueError:
#         return None
#     real = (REAL_SANDBOX_ROOT / str(rel)).resolve(strict=False)
#     # Final real-filesystem safety check as well.
#     try:
#         real.relative_to(REAL_SANDBOX_ROOT)
#     except ValueError:
#         return None
#     return real


# def canonical_host(url: str):
#     parsed = urlparse(url)
#     if parsed.scheme not in {"http", "https"}:
#         raise ValueError("unsupported scheme")
#     if not parsed.hostname:
#         raise ValueError("missing host")
#     host = parsed.hostname.rstrip(".").lower()
#     if parsed.username is not None or parsed.password is not None:
#         raise ValueError("userinfo not allowed")
#     # Reject IP-literal hosts outright — allowed hosts are always domain names.
#     try:
#         ipaddress.ip_address(host)
#         raise ValueError("IP literal hosts are not allowed")
#     except ValueError as e:
#         if "IP literal" in str(e):
#             raise
#         # not an IP address string — fine, continue
#     return parsed.scheme, host, parsed


# def is_private_or_special_ip(ip_str: str) -> bool:
#     try:
#         ip = ipaddress.ip_address(ip_str)
#         return (
#             ip.is_private
#             or ip.is_loopback
#             or ip.is_link_local
#             or ip.is_reserved
#             or ip.is_multicast
#             or ip.is_unspecified
#         )
#     except ValueError:
#         return False


# def host_resolves_to_public_ip(host: str) -> bool:
#     try:
#         infos = socket.getaddrinfo(host, None)
#     except Exception:
#         return False
#     if not infos:
#         return False
#     for info in infos:
#         ip_str = info[4][0]
#         if is_private_or_special_ip(ip_str):
#             return False
#     return True


# # ------------------------- tool implementations -------------------------

# def do_read_file(raw_path: str) -> Dict[str, Any]:
#     virtual = resolve_virtual_path(raw_path)
#     if virtual is None:
#         return {"action": "block", "reason": "Malformed path."}

#     real = virtual_to_real(virtual)
#     if real is None:
#         return {"action": "block", "reason": "Path escapes the sandbox root."}

#     if not real.exists() or not real.is_file():
#         return {"action": "block", "reason": "File does not exist inside the sandbox."}

#     try:
#         txt = real.read_text(encoding="utf-8", errors="replace")
#     except Exception as e:
#         return {"action": "block", "reason": f"Read failed: {type(e).__name__}"}

#     return {"action": "allow", "reason": "Path resolves inside the sandbox root.", "result": txt}


# def _validate_host_for_fetch(host: str) -> str | None:
#     """Return a block reason, or None if the host is OK to fetch."""
#     if host not in ALLOWED_HOSTS:
#         return "Host is not on the exact allowlist."
#     if is_private_or_special_ip(host):
#         return "Host is a private/special IP literal."
#     if not host_resolves_to_public_ip(host):
#         return "Host resolves to a private/special address."
#     return None


# def do_fetch_url(url: str) -> Dict[str, Any]:
#     # Reject userinfo-confusion tricks outright.
#     if "@" in url:
#         return {"action": "block", "reason": "URL contains userinfo/@ which is not permitted."}

#     try:
#         _, host, _ = canonical_host(url)
#     except Exception as e:
#         return {"action": "block", "reason": f"Invalid URL: {type(e).__name__}"}

#     reason = _validate_host_for_fetch(host)
#     if reason:
#         return {"action": "block", "reason": reason}

#     try:
#         resp = requests.get(
#             url, timeout=8, allow_redirects=False,
#             headers={"User-Agent": "ga5-redteam/1.0"},
#         )
#     except Exception as e:
#         return {"action": "block", "reason": f"Fetch failed: {type(e).__name__}"}

#     # Follow redirects manually, re-validating every hop against the same
#     # allowlist + private-IP + userinfo checks. Only an allowlisted, public
#     # target is ever actually requested.
#     hops = 0
#     while 300 <= resp.status_code < 400 and hops < 5:
#         location = resp.headers.get("Location")
#         if not location:
#             break
#         next_url = location if "://" in location else requests.compat.urljoin(resp.url, location)

#         if "@" in next_url:
#             return {"action": "block", "reason": "Redirect target contains userinfo/@."}

#         try:
#             _, next_host, _ = canonical_host(next_url)
#         except Exception:
#             return {"action": "block", "reason": "Redirect target URL is invalid."}

#         reason = _validate_host_for_fetch(next_host)
#         if reason:
#             return {"action": "block", "reason": f"Redirect blocked: {reason}"}

#         try:
#             resp = requests.get(
#                 next_url, timeout=8, allow_redirects=False,
#                 headers={"User-Agent": "ga5-redteam/1.0"},
#             )
#         except Exception as e:
#             return {"action": "block", "reason": f"Redirect fetch failed: {type(e).__name__}"}
#         hops += 1

#     if 300 <= resp.status_code < 400:
#         return {"action": "block", "reason": "Too many redirects."}

#     return {
#         "action": "allow",
#         "reason": "Host is exactly allowlisted and resolves publicly.",
#         "result": {"status_code": resp.status_code, "content": resp.text[:50_000]},
#     }


# # ------------------------- route -------------------------

# @APP.post("/q8/check")
# async def q8_check(request: Request):
#     raw = await request.body()
#     data = ensure_json(raw)

#     tool = data.get("tool")
#     args = data.get("arguments", {}) or {}

#     if tool == "read_file":
#         result = do_read_file(str(args.get("path", "")))
#     elif tool == "fetch_url":
#         result = do_fetch_url(str(args.get("url", "")))
#     else:
#         result = {"action": "block", "reason": "Unknown tool."}

#     return JSONResponse(result)


# @APP.get("/health")
# def health():
#     return {"ok": True}


# if __name__ == "__main__":
#     uvicorn.run(APP, host="0.0.0.0", port=8000)



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
# The grader references this "logical" absolute path in its requests/spec.
LOGICAL_SANDBOX_ROOT = PurePosixPath("/srv/agent-redteam/sandbox-fc10547e85")
LOGICAL_OUTSIDE_DIR = PurePosixPath("/srv/agent-redteam/outside-5bc873bb")

# Where we actually store the bytes on disk (writable on Render's free tier).
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
    """
    Interpret raw_path the way the grader intends it (relative to, or under,
    the logical sandbox root), fully collapse '..' segments in POSIX terms,
    and return the resulting *virtual* absolute path -- or None if it's not
    a well-formed path at all.
    """
    p = PurePosixPath(raw_path)
    if not p.is_absolute():
        virtual = LOGICAL_SANDBOX_ROOT / p
    else:
        virtual = p

    # Manually collapse '.' and '..' components (PurePosixPath doesn't do this).
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
    normalized = PurePosixPath(*parts)
    return normalized


def virtual_to_real(virtual: PurePosixPath) -> Optional[Path]:
    """Map a normalized virtual path under the logical sandbox root to the
    real writable path on disk. Returns None if it doesn't map anywhere we
    actually serve content from (i.e. outside sandbox)."""
    try:
        rel = virtual.relative_to(LOGICAL_SANDBOX_ROOT)
    except ValueError:
        return None
    real = (REAL_SANDBOX_ROOT / str(rel)).resolve(strict=False)
    # Final real-filesystem safety check as well.
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
    # Reject IP-literal hosts outright — allowed hosts are always domain names.
    try:
        ipaddress.ip_address(host)
        raise ValueError("IP literal hosts are not allowed")
    except ValueError as e:
        if "IP literal" in str(e):
            raise
        # not an IP address string — fine, continue
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


def _validate_host_for_fetch(host: str) -> Optional[str]:
    """Return a block reason, or None if the host is OK to fetch (name-level only)."""
    if host not in ALLOWED_HOSTS:
        return "Host is not on the exact allowlist."
    if is_private_or_special_ip(host):
        return "Host is a private/special IP literal."
    return None


# ------------------------- DNS pinning (anti-rebinding) -------------------------

_original_getaddrinfo = socket.getaddrinfo


@contextlib.contextmanager
def pin_dns(hostname: str, pinned_ip: str):
    """Force socket.getaddrinfo to return only the pre-validated IP for this
    exact hostname during the enclosed block. This closes the TOCTOU window
    where our validation resolves one IP but the actual outbound connection
    (a second, independent DNS lookup inside `requests`) could resolve to a
    different, private/internal address (DNS rebinding)."""

    def patched_getaddrinfo(host, *args, **kwargs):
        if host == hostname:
            return _original_getaddrinfo(pinned_ip, *args, **kwargs)
        return _original_getaddrinfo(host, *args, **kwargs)

    socket.getaddrinfo = patched_getaddrinfo
    try:
        yield
    finally:
        socket.getaddrinfo = _original_getaddrinfo


def resolve_and_validate_ip(host: str) -> Optional[str]:
    """Resolve host once, confirm every candidate address is public, and
    return the single IP we will pin the connection to. None if unsafe or
    unresolvable."""
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return None
    if not infos:
        return None
    ips = {info[4][0] for info in infos}
    for ip_str in ips:
        if is_private_or_special_ip(ip_str):
            return None
    return next(iter(ips))


def _pinned_get(url: str, host: str):
    pinned_ip = resolve_and_validate_ip(host)
    if pinned_ip is None:
        raise ValueError("host does not resolve to a public IP")
    with pin_dns(host, pinned_ip):
        return requests.get(
            url, timeout=8, allow_redirects=False,
            headers={"User-Agent": "ga5-redteam/1.0", "Host": host},
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
        resp = _pinned_get(url, host)
    except Exception as e:
        return {"action": "block", "reason": f"Fetch failed: {type(e).__name__}"}

    # Follow redirects manually, re-validating (and re-pinning) every hop.
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
            resp = _pinned_get(next_url, next_host)
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
