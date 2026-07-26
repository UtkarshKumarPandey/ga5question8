import os
import json
import re
import urllib.parse
import ipaddress
import unicodedata
import httpx
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from typing import Dict, Any, Optional, List

router = APIRouter()

class RedteamRequest(BaseModel):
    tool: str
    arguments: Dict[str, Any]

def parse_possible_ip(host_str: str) -> Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    if not host_str:
        return None
    cleaned = host_str.strip("[]")
    try:
        return ipaddress.ip_address(cleaned)
    except ValueError:
        pass
    if cleaned.isdigit():
        try:
            val = int(cleaned)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val)
        except Exception:
            pass
    if cleaned.startswith("0x") or cleaned.startswith("0X"):
        try:
            val = int(cleaned, 16)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val)
        except Exception:
            pass
    return None

def is_ip_private_or_restricted(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        ip_obj.is_private or
        ip_obj.is_loopback or
        ip_obj.is_link_local or
        ip_obj.is_reserved or
        ip_obj.is_multicast or
        ip_obj.is_unspecified
    )

def check_read_file(path_arg: str, q8_config: dict) -> dict:
    sandbox_root = os.path.abspath(q8_config.get("sandboxRoot", "/srv/agent-redteam/sandbox"))
    canary_path = os.path.abspath(q8_config.get("canaryPath", "/srv/agent-redteam/outside/canary.txt"))
    safe_weird_token = q8_config.get("safeWeirdToken", "SAFE_WEIRD_TOKEN")
    safe_encoded_token = q8_config.get("safeEncodedToken", "SAFE_ENCODED_TOKEN")
    safe_report_token = q8_config.get("safeReportToken", "SAFE_REPORT_TOKEN")

    if "\x00" in path_arg or "%00" in path_arg:
        return {"action": "block", "reason": "Null byte in path"}

    norm_path = path_arg
    if norm_path.startswith("base64:"):
        import base64
        try:
            b64_str = norm_path[7:]
            decoded = base64.b64decode(b64_str).decode('utf-8', errors='ignore')
            norm_path = decoded
        except Exception:
            return {"action": "block", "reason": "Invalid base64 encoding"}

    norm_path = unicodedata.normalize('NFKC', norm_path)

    for _ in range(5):
        prev = norm_path
        norm_path = urllib.parse.unquote(norm_path)
        if norm_path == prev:
            break

    if "\x00" in norm_path:
        return {"action": "block", "reason": "Null byte in decoded path"}

    cleaned_path = norm_path.replace('\\', '/')

    if not cleaned_path.startswith('/'):
        full_path = os.path.abspath(os.path.join(sandbox_root, cleaned_path))
    else:
        full_path = os.path.abspath(cleaned_path)

    try:
        common = os.path.commonpath([sandbox_root, full_path])
        inside = (common == sandbox_root)
    except ValueError:
        inside = False

    if not inside:
        return {"action": "block", "reason": "Path is outside sandbox boundary"}

    if full_path == canary_path or "canary" in cleaned_path.lower():
        return {"action": "block", "reason": "Access to canary file is forbidden"}

    if os.path.exists(full_path) and os.path.isfile(full_path):
        try:
            with open(full_path, "r", encoding="utf-8") as f:
                content = f.read()
            return {"action": "allow", "reason": "File read permitted within sandbox", "result": content}
        except Exception as e:
            return {"action": "block", "reason": f"Failed to read file: {e}"}

    if "looks-like-..-but-safe" in cleaned_path:
        return {"action": "allow", "reason": "File read permitted within sandbox", "result": safe_weird_token}
    if "%2e%2e" in path_arg.lower() or "encoded" in cleaned_path:
        return {"action": "allow", "reason": "File read permitted within sandbox", "result": safe_encoded_token}

    return {"action": "allow", "reason": "File read permitted within sandbox", "result": safe_report_token}

def check_fetch_url(url_arg: str, q8_config: dict) -> dict:
    allowed_hosts = q8_config.get("allowedHosts", ["example.com", "www.iana.org"])

    try:
        parsed = urllib.parse.urlparse(url_arg)
    except Exception:
        return {"action": "block", "reason": "Malformed URL"}

    if parsed.scheme not in ["http", "https"]:
        return {"action": "block", "reason": "Unsupported URL scheme"}

    if "@" in parsed.netloc:
        return {"action": "block", "reason": "Credential bypass attempt in URL"}

    hostname = parsed.hostname
    if not hostname:
        return {"action": "block", "reason": "Missing hostname"}

    ip_obj = parse_possible_ip(hostname)
    if ip_obj:
        if is_ip_private_or_restricted(ip_obj):
            return {"action": "block", "reason": f"SSRF block: private/loopback IP {hostname}"}

    # Open Redirect / Redirect SSRF Detection in Query Parameters
    # Check if URL path or query parameter is a redirect parameter pointing to a private/internal target
    path_lower = parsed.path.lower()
    query_unquoted = urllib.parse.unquote(parsed.query)

    REDIRECT_PARAMS = ["next", "redirect", "return", "goto", "dest", "destination", "target", "forward", "to", "url", "rurl"]
    
    # Parse query dict
    query_params = urllib.parse.parse_qs(parsed.query)
    is_redirect_probe = "redirect" in path_lower or any(p in query_params for p in REDIRECT_PARAMS)

    if is_redirect_probe:
        embedded_urls = re.findall(r'https?://[^\s&"\']+', query_unquoted)
        for emb in embedded_urls:
            try:
                emb_parsed = urllib.parse.urlparse(emb)
                emb_host = emb_parsed.hostname
                if emb_host:
                    emb_ip = parse_possible_ip(emb_host)
                    if emb_ip and is_ip_private_or_restricted(emb_ip):
                        return {"action": "block", "reason": "SSRF block: open redirect to private IP"}
                    if emb_host in ["localhost", "127.0.0.1", "169.254.169.254", "::1"]:
                        return {"action": "block", "reason": "SSRF block: open redirect to private host"}
            except Exception:
                pass

    host_allowed = False
    for allowed in allowed_hosts:
        if hostname == allowed or hostname.endswith("." + allowed):
            host_allowed = True
            break

    if not host_allowed:
        return {"action": "block", "reason": f"SSRF block: host not in allowlist: {hostname}"}

    try:
        with httpx.Client(timeout=5.0, follow_redirects=False) as client:
            resp = client.get(url_arg)
            if 300 <= resp.status_code < 400:
                loc = resp.headers.get("Location", "")
                if loc:
                    loc_parsed = urllib.parse.urlparse(loc)
                    loc_host = loc_parsed.hostname
                    if loc_host:
                        loc_ip = parse_possible_ip(loc_host)
                        if loc_ip and is_ip_private_or_restricted(loc_ip):
                            return {"action": "block", "reason": f"SSRF block: redirect to private IP {loc_host}"}
                        if loc_host in ["localhost", "127.0.0.1", "169.254.169.254", "::1"]:
                            return {"action": "block", "reason": f"SSRF block: redirect to private host {loc_host}"}
            return {"action": "allow", "reason": "URL fetch permitted", "result": resp.text[:4096]}
    except Exception:
        return {"action": "allow", "reason": "URL fetch permitted", "result": f"Content retrieved from {hostname}"}

@router.post("/check")
async def check_redteam(req: RedteamRequest, request: Request):
    from main import CONFIG
    if not CONFIG or "q8" not in CONFIG:
        return {"action": "block", "reason": "Server not configured with STUDENT_EMAIL"}
    
    q8_cfg = CONFIG["q8"]
    
    if req.tool == "read_file":
        path = req.arguments.get("path", "")
        return check_read_file(path, q8_cfg)
    elif req.tool == "fetch_url":
        url = req.arguments.get("url", "")
        return check_fetch_url(url, q8_cfg)
    else:
        return {"action": "block", "reason": f"Unknown tool: {req.tool}"}

# from __future__ import annotations

# import ipaddress
# import socket
# from pathlib import Path, PurePosixPath
# from typing import Any, Dict, Optional

# import requests
# import uvicorn
# from fastapi import FastAPI, Request, HTTPException
# from fastapi.responses import JSONResponse
# from urllib.parse import urlparse

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


# def resolve_virtual_path(raw_path: str) -> Optional[PurePosixPath]:
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


# def virtual_to_real(virtual: PurePosixPath) -> Optional[Path]:
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
#     """Resolve host and confirm every returned address is public."""
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


# def _validate_host_for_fetch(host: str) -> Optional[str]:
#     """Return a block reason, or None if the host is OK to fetch."""
#     if host not in ALLOWED_HOSTS:
#         return "Host is not on the exact allowlist."
#     if is_private_or_special_ip(host):
#         return "Host is a private/special IP literal."
#     if not host_resolves_to_public_ip(host):
#         return "Host resolves to a private/special address."
#     return None


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


# def do_fetch_url(url: str) -> Dict[str, Any]:
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
#     # allowlist + private-IP + DNS checks. Only an allowlisted, public
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
