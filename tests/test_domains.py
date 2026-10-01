import pytest

from app.domains import InvalidDomain, create_challenge, normalize_domain


@pytest.mark.parametrize("raw, expected", [
    ("Example.FR", "example.fr"),
    ("https://www.example.fr/path?q=1", "example.fr"),
    ("example.fr.", "example.fr"),
    ("sub.example.co.uk:8443", "sub.example.co.uk"),
    ("café.fr", "xn--caf-dma.fr"),
])
def test_normalize_valid(raw, expected):
    assert normalize_domain(raw) == expected


@pytest.mark.parametrize("raw", [
    "", "localhost", "192.168.1.1", "*.example.fr", "exa mple.fr",
    "-bad.example.fr", "user@example.fr", "example.fr; rm -rf /", "a" * 64 + ".fr",
])
def test_normalize_rejects(raw):
    with pytest.raises(InvalidDomain):
        normalize_domain(raw)


def test_challenge_format():
    ch = create_challenge("user1", "https://Example.fr")
    assert ch.domain == "example.fr"
    assert ch.record_name == "_surfacewatch-verify.example.fr"
    assert ch.record_value.startswith("sw-verify=")


def test_tokens_are_unique():
    assert create_challenge("u", "example.fr").record_value != create_challenge("u", "example.fr").record_value


class _Rdata:
    def __init__(self, value):
        self.strings = [value.encode()]


def _fake_dns(monkeypatch, records):
    """Serve TXT lookups from a {name: [values]} dict instead of the network."""
    import dns.resolver

    from app import domains

    class FakeResolver:
        def resolve(self, name, rtype):
            if name not in records:
                raise dns.resolver.NXDOMAIN()
            return [_Rdata(v) for v in records[name]]

    monkeypatch.setattr(domains, "_authoritative_resolver", lambda name, timeout: FakeResolver())
    monkeypatch.setattr(domains.dns.resolver, "Resolver", lambda *a, **k: FakeResolver())


@pytest.mark.parametrize("records, reason", [
    ({"_sw.example.fr": ["sw-verify=abc"]}, "ok"),
    ({"_sw.example.fr": [' "sw-verify=abc" ']}, "ok"),
    ({"_sw.example.fr": ["sw-verify=old"]}, "mismatch"),
    ({"_sw.example.fr.example.fr": ["sw-verify=abc"]}, "doubled_name"),
    ({}, "not_found"),
])
def test_lookup_txt_record(monkeypatch, records, reason):
    from app.domains import lookup_txt_record
    _fake_dns(monkeypatch, records)
    assert lookup_txt_record("_sw.example.fr", "sw-verify=abc").reason == reason
