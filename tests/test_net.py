"""SSRF guard tests (Fable C1).

Literal-IP cases need no network: getaddrinfo resolves a literal address offline,
so 8.8.8.8 exercises the allow-path and the private/loopback/metadata literals
exercise the block-path deterministically.
"""
from __future__ import annotations

import asyncio
import socket

import httpx
import pytest
from fastapi.testclient import TestClient

from app import main, net


@pytest.mark.parametrize("url", [
    "http://127.0.0.1/",
    "http://localhost/",              # resolves to loopback
    "http://169.254.169.254/latest/meta-data/",  # cloud metadata
    "http://10.0.0.5/",
    "http://192.168.1.1/",
    "http://172.16.0.1/",
    "http://[::1]/",                  # IPv6 loopback
    "http://0.0.0.0/",                # unspecified
    "file:///etc/passwd",             # scheme not allowed
    "ftp://example.com/",             # scheme not allowed
    "gopher://127.0.0.1:6379/",       # scheme not allowed
    "http://",                        # no host
    "not a url",
    "http://8.8.8.8:999999/",         # port out of range -> UnsafeURLError, not 500
    "http://8.8.8.8:notaport/",       # non-numeric port
])
def test_assert_public_url_blocks_unsafe(url):
    with pytest.raises(net.UnsafeURLError):
        net.assert_public_url(url)


@pytest.mark.parametrize("url", [
    "http://8.8.8.8/",                # public literal, no DNS needed
    "https://8.8.8.8/skill.md",
])
def test_assert_public_url_allows_public_literal(url):
    net.assert_public_url(url)  # must not raise


def test_ipv4_mapped_ipv6_loopback_blocked():
    # ::ffff:127.0.0.1 must be judged on the embedded v4 address, not the v6 wrapper.
    with pytest.raises(net.UnsafeURLError):
        net.assert_public_url("http://[::ffff:127.0.0.1]/")


def test_verify_endpoint_rejects_internal_agent_url():
    client = TestClient(main.app)
    r = client.post("/verify", json={"agent_url": "http://169.254.169.254/latest/meta-data/"})
    assert r.status_code == 400
    assert "rejected" in r.text.lower()


@pytest.mark.parametrize("a,b,expected", [
    ("https://agent.example/api", "https://agent.example/skill.md", True),
    ("https://agent.example:443/api", "https://agent.example/skill.md", True),  # default port
    ("https://Agent.Example/api", "https://agent.example/skill.md", True),      # case-insensitive host
    ("https://agent.example/api", "https://evil.example/skill.md", False),      # different host
    ("https://agent.example/api", "http://agent.example/skill.md", False),      # different scheme
    ("https://agent.example/api", "https://agent.example:8443/skill.md", False),# different port
])
def test_same_origin(a, b, expected):
    assert net.same_origin(a, b) is expected


def test_verify_endpoint_rejects_cross_origin_skill_md(monkeypatch):
    # M10: a caller can't point us at a competitor's agent with a malicious skill card
    # hosted elsewhere.
    client = TestClient(main.app)
    r = client.post("/verify", json={"agent_url": "http://8.8.8.8/api/send",
                                     "skill_md_url": "http://8.8.4.4/skill.md"})
    assert r.status_code == 400
    assert "same-origin" in r.text


def test_verify_endpoint_returns_400_not_500_on_bad_port():
    client = TestClient(main.app)
    r = client.post("/verify", json={"agent_url": "http://8.8.8.8:999999/"})
    assert r.status_code == 400, r.text


def test_verify_endpoint_rejects_internal_skill_md_url():
    client = TestClient(main.app)
    r = client.post("/verify", json={"agent_url": "http://8.8.8.8/api/send",
                                     "skill_md_url": "http://127.0.0.1/skill.md"})
    assert r.status_code == 400
    assert "skill_md_url" in r.text


def test_safe_request_pins_to_resolved_ip(monkeypatch):
    # DNS-rebinding defence: the request must CONNECT to the exact IP we validated
    # (URL host rewritten to the IP) while the Host header keeps the real hostname.
    monkeypatch.setattr(net, "_resolve_public_ips", lambda host, port: ["93.184.216.34"])
    seen = {}

    def handler(request):
        seen["conn_host"] = request.url.host
        seen["host_header"] = request.headers.get("host")
        return httpx.Response(200, text="ok")

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            return await net.safe_request(c, "GET", "https://example.com/path?q=1")

    status, body = asyncio.run(go())
    assert status == 200 and body == "ok"
    assert seen["conn_host"] == "93.184.216.34"   # connected to the pinned IP
    assert seen["host_header"] == "example.com"    # original Host preserved


def test_resolve_fails_closed_on_mixed_public_private(monkeypatch):
    # split-horizon: if a host resolves to BOTH a public and a private address, refuse.
    def fake_getaddrinfo(host, port, *a, **k):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", port))]
    monkeypatch.setattr(net.socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(net.UnsafeURLError):
        net.assert_public_url("http://sneaky.example/")
