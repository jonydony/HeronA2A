"""SSRF guard for every outbound fetch to a caller-supplied URL.

POST /verify takes agent_url + skill_md_url from an untrusted caller, Heron fetches
them, and reflects response bodies into a PUBLIC signed record. Unguarded, that is a
server-side request forgery + exfiltration primitive: a caller points Heron at
http://169.254.169.254/ (cloud metadata) or an internal service and reads the
reflected body out of the public registry.

Defence, layered:
  1. scheme allowlist        http / https only (no file://, gopher://, etc.)
  2. host resolution check    resolve the hostname and refuse if ANY resolved
                              address is private / loopback / link-local / reserved /
                              multicast / unspecified (blocks metadata + internal)
  3. no blind redirects       callers pass follow_redirects=False; a 302 to an
                              internal host would otherwise bypass the host check
  4. body cap                 reads are byte-capped so a huge internal response
                              can't be used for memory abuse or bulk exfil

Residual (documented, accepted for this demo artifact): DNS rebinding between the
check and the connect (TOCTOU). Closing it fully needs pinning the socket to the
validated IP; out of scope here.
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit

import httpx

# Bodies we reflect are truncated to a few hundred chars downstream; this is the
# hard download ceiling so a hostile/internal endpoint can't stream us gigabytes.
MAX_BODY_BYTES = 64 * 1024


class UnsafeURLError(ValueError):
    """Raised when a caller-supplied URL is not safe to fetch."""


def _ip_is_blocked(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    # IPv4-mapped IPv6 (::ffff:127.0.0.1) must be judged on the embedded v4 addr.
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local     # 169.254.0.0/16 — cloud metadata lives here
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


def assert_public_url(url: str | None) -> None:
    """Raise UnsafeURLError unless `url` is http(s) and every resolved IP is public."""
    if not url or not isinstance(url, str):
        raise UnsafeURLError("missing or non-string URL")
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise UnsafeURLError(f"scheme not allowed: {parts.scheme or '(none)'}")
    host = parts.hostname
    if not host:
        raise UnsafeURLError("URL has no host")
    # A literal IP still has to pass the range check.
    try:
        infos = socket.getaddrinfo(host, parts.port or (443 if parts.scheme == "https" else 80),
                                   proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise UnsafeURLError(f"host does not resolve: {host} ({exc})") from exc
    ips = {info[4][0] for info in infos}
    if not ips:
        raise UnsafeURLError(f"host resolves to no address: {host}")
    for ip in ips:
        if _ip_is_blocked(ip):
            raise UnsafeURLError(f"host {host} resolves to a non-public address ({ip})")


async def safe_request(
    client: httpx.AsyncClient,
    method: str,
    url: str | None,
    *,
    params=None,
    json=None,
    headers=None,
    max_bytes: int = MAX_BODY_BYTES,
) -> tuple[int, str]:
    """Guarded outbound call. Validates the URL, refuses redirects, byte-caps the body.
    Returns (status_code, text). Raises UnsafeURLError for a blocked URL."""
    assert_public_url(url)
    req = client.build_request(method.upper(), url, params=params, json=json, headers=headers)
    r = await client.send(req, follow_redirects=False)
    try:
        if r.is_redirect:
            loc = r.headers.get("location", "")
            return r.status_code, f"error: refusing to follow redirect to {loc[:120]}"
        chunks, total = [], 0
        async for chunk in r.aiter_bytes():
            chunks.append(chunk)
            total += len(chunk)
            if total >= max_bytes:
                break
        raw = b"".join(chunks)[:max_bytes]
        return r.status_code, raw.decode("utf-8", "replace")
    finally:
        await r.aclose()
