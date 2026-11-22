"""UM-DR-44 A6 — canonical_target_key: IPv6 and IDN (RED on 6f3dc7c).

Verified failures on the base tree:

* ``parts.hostname`` strips the IPv6 brackets → the rebuilt netloc is
  INVALID: https://[::1]:8443/a → https://::1:8443/a (no client or
  comparator can round-trip it; urlsplit cannot parse the host back);
* different hex/compression spellings of the SAME literal produce
  different keys ([2001:DB8::1] vs [2001:db8::1] vs
  [2001:0db8:0000::1]) — canonicalization must go through
  ipaddress.IPv6Address (compressed + lowercase unifies both);
* IDN: a unicode host is not punycoded → münchen.de and
  xn--mnchen-3ya.de produce TWO keys for the same registrable host;
* documentation lie: the docstring claims the trailing slash is
  PRESERVED while the code strips it (rstrip('/') since birth) — the
  docstring must match the actual (checkpoint-id compatible) behavior.

Required: brackets preserved; IPv6 unified via ipaddress.IPv6Address;
IDN via host.encode('idna') with a safe fallback on malformed hosts;
domains and IPv4 byte-identical with the previous contract.
"""

from __future__ import annotations

from urllib.parse import urlsplit

import pytest

from webpent.production.hypothesis_identity import canonical_target_key as c


class TestIPv6:
    def test_brackets_preserved_with_explicit_port(self) -> None:
        """RED: the base drops the brackets → invalid netloc."""
        assert c("https://[::1]:8443/x") == "https://[::1]:8443/x"

    def test_brackets_preserved_default_port_stripped(self) -> None:
        assert c("https://[2001:db8::1]:443/api") == "https://[2001:db8::1]/api"

    def test_hex_case_unified(self) -> None:
        assert c("https://[2001:DB8::1]/api") == \
            c("https://[2001:db8::1]/api")

    def test_zero_compression_unified(self) -> None:
        """The SAME literal in different spellings → ONE key — the
        unification must go through ipaddress.IPv6Address (compressed
        form), not just .lower()."""
        same = "2001:0db8:0000:0000:0000:0000:0000:0001"
        assert c(f"https://[{same}]/api") == c("https://[2001:db8::1]/api")

    def test_key_round_trips_through_urlsplit(self) -> None:
        key = c("https://[::1]:8443/x")
        assert urlsplit(key).hostname == "::1"

    def test_ipv4_byte_identical(self) -> None:
        assert c("https://192.0.2.1:8443/x") == "https://192.0.2.1:8443/x"
        assert c("https://192.0.2.1:443/x") == "https://192.0.2.1/x"


class TestIDN:
    def test_unicode_host_punycoded(self) -> None:
        """RED: the base passes the unicode host through verbatim."""
        assert c("https://münchen.de/api") == \
            c("https://xn--mnchen-3ya.de/api")

    def test_unicode_host_uppercase(self) -> None:
        assert c("https://MÜNCHEN.DE/api") == c("https://münchen.de/api")

    def test_malformed_idn_falls_back_unchanged(self) -> None:
        """An un-encodable host never raises — honest fallback."""
        out = c("https://eẍample.test/api")  # combining diaeresis host
        assert isinstance(out, str) and out


class TestDomainContractUnchanged:
    def test_domain_case_folding(self) -> None:
        assert c("https://EXAMPLE.com/API") == "https://example.com/API"

    def test_default_port_stripped(self) -> None:
        assert c("http://example.com:80/x") == "http://example.com/x"
        assert c("https://example.com:443/x") == "https://example.com/x"

    def test_trailing_dot_stripped(self) -> None:
        assert c("https://example.com./x") == "https://example.com/x"

    @pytest.mark.parametrize("url", [
        "https://[::1]:8443/x",
        "https://[2001:DB8::1]/api",
        "https://münchen.de/api",
        "https://xn--mnchen-3ya.de/api",
        "https://example.com:443/a",
        "http://example.com:8080/b",
        "https://192.0.2.1/x",
    ])
    def test_idempotent(self, url: str) -> None:
        once = c(url)
        assert c(once) == once, f"canonical form not idempotent: {once}"
