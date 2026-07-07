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
  3. IP pinning               safe_request resolves ONCE, validates, then connects to
                              that exact IP (URL host rewritten to the IP, Host header
                              + TLS SNI preserved). httpx never re-resolves, so a
                              low-TTL rebinding record can't swap in an internal IP
                              between the check and the connect (closes the TOCTOU).
  4. no blind redirects       a 302 to an internal host is not followed (it would be a
                              fresh, unvalidated hop)
  5. body cap                 reads are byte-capped so a huge internal response can't
                              be used for memory abuse or bulk exfil
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit, urlunsplit

import httpx

# Bodies we reflect are truncated to a few hundred chars downstream; this is the
# hard download ceiling so a hostile/internal endpoint can't stream us gigabytes.
MAX_BODY_BYTES = 64 * 1024


class UnsafeURLError(ValueError):
    """Raised when a caller-supplied URL is not safe to fetch."""


def _ip_is_blocked(ip: str) -> bool:
    try:
        # getaddrinfo can hand back a scoped address (fe80::1%eth0); ip_address would
        # raise on that. Treat anything unparseable as blocked (fail closed).
        addr = ipaddress.ip_address(ip.split("%", 1)[0])
    except ValueError:
        return True
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


def _split_host_port(url: str | None) -> tuple[str, str, int]:
    """Parse + validate the shape of a URL. Returns (scheme, host, port). Only ever
    raises UnsafeURLError (never a bare ValueError), so callers get a clean 400."""
    if not url or not isinstance(url, str):
        raise UnsafeURLError("missing or non-string URL")
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise UnsafeURLError(f"scheme not allowed: {parts.scheme or '(none)'}")
    host = parts.hostname
    if not host:
        raise UnsafeURLError("URL has no host")
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError as exc:
        raise UnsafeURLError(f"invalid port in URL ({exc})") from exc
    return parts.scheme, host, port


def _resolve_public_ips(host: str, port: int) -> list[str]:
    """Resolve `host` and return its addresses, or raise UnsafeURLError if ANY resolved
    address is non-public (fail closed on a split-horizon / mixed result)."""
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise UnsafeURLError(f"host does not resolve: {host} ({exc})") from exc
    ips = list(dict.fromkeys(info[4][0] for info in infos))  # de-dup, keep order
    if not ips:
        raise UnsafeURLError(f"host resolves to no address: {host}")
    for ip in ips:
        if _ip_is_blocked(ip):
            raise UnsafeURLError(f"host {host} resolves to a non-public address ({ip})")
    return ips


def assert_public_url(url: str | None) -> None:
    """Raise UnsafeURLError unless `url` is http(s) and every resolved IP is public.
    Used as the up-front /verify gate; safe_request re-validates AND pins at fetch time."""
    scheme, host, port = _split_host_port(url)
    _resolve_public_ips(host, port)


def _authority(host: str, port: int, scheme: str) -> str:
    h = f"[{host}]" if ":" in host else host
    default = 443 if scheme == "https" else 80
    return h if port == default else f"{h}:{port}"


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
    """Guarded outbound call. Resolves + validates the host ONCE, then connects to that
    exact IP (no re-resolution -> no DNS rebinding), refuses redirects, byte-caps the
    body. Returns (status_code, text). Raises UnsafeURLError for a blocked URL."""
    scheme, host, port = _split_host_port(url)
    pin_ip = _resolve_public_ips(host, port)[0]

    # Rebuild the URL against the pinned IP so httpx connects there and never resolves
    # the hostname again. Preserve the original Host header and drive TLS SNI + cert
    # verification with the real hostname via the sni_hostname extension.
    parts = urlsplit(url)
    ip_netloc = f"[{pin_ip}]" if ":" in pin_ip else pin_ip
    if parts.port:
        ip_netloc += f":{port}"
    pinned_url = urlunsplit((scheme, ip_netloc, parts.path or "/", parts.query, ""))

    hdrs = dict(headers or {})
    hdrs["Host"] = _authority(host, port, scheme)
    req = client.build_request(
        method.upper(), pinned_url, params=params, json=json, headers=hdrs,
        extensions={"sni_hostname": host},
    )
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
