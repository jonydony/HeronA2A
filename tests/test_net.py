"""SSRF guard tests (Fable C1).

Literal-IP cases need no network: getaddrinfo resolves a literal address offline,
so 8.8.8.8 exercises the allow-path and the private/loopback/metadata literals
exercise the block-path deterministically.
"""
from __future__ import annotations

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


def test_verify_endpoint_rejects_internal_skill_md_url():
    client = TestClient(main.app)
    r = client.post("/verify", json={"agent_url": "http://8.8.8.8/api/send",
                                     "skill_md_url": "http://127.0.0.1/skill.md"})
    assert r.status_code == 400
    assert "skill_md_url" in r.text
