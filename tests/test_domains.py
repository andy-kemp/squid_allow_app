import pytest

from pawpilot import domains as D


@pytest.mark.parametrize("raw, subdomains, expected", [
    ("Example.COM", None, "example.com"),
    (" .example.com ", None, ".example.com"),
    ("*.example.com", None, ".example.com"),
    ("https://portal.azure.com/#home", None, "portal.azure.com"),
    ("login.live.com:443", None, "login.live.com"),
    ("example.com.", None, "example.com"),
    ("example.com", True, ".example.com"),
    (".example.com", False, "example.com"),
    ("xn--bcher-kva.example", None, "xn--bcher-kva.example"),
])
def test_normalise(raw, subdomains, expected):
    assert D.normalise(raw, subdomains) == expected


@pytest.mark.parametrize("raw", [
    "", "   ", "localhost", "10.0.0.1", "exa mple.com", "example..com", "-bad.example.com",
    "example.com\n.evil.com", 'x.com" include "/etc/shadow', "a" * 64 + ".com", "under_score.example.com",
    "[::1]", "example.com;rm -rf", "#comment.com",
])
def test_normalise_rejects(raw):
    with pytest.raises(D.DomainError):
        D.normalise(raw)


def test_covers_matches_like_squid():
    assert D.covers(".example.com", "example.com")
    assert D.covers(".example.com", "a.b.example.com")
    assert not D.covers(".example.com", "notexample.com")
    assert D.covers("example.com", "example.com")
    assert not D.covers("example.com", "www.example.com")


def test_matcher_and_effective():
    entries = [".microsoft.com", "graph.microsoft.com", ".login.microsoft.com", "example.com", ".example.org",
               "example.org"]
    m = D.Matcher(e for e in entries)  # generators must work too
    assert m.match("a.b.microsoft.com") == ".microsoft.com"
    assert m.match("example.com") == "example.com"
    assert m.match("www.example.com") is None
    keep, redundant = D.effective(entries)
    assert keep == ["example.com", ".example.org", ".microsoft.com"]
    assert redundant == {"graph.microsoft.com": ".microsoft.com", ".login.microsoft.com": ".microsoft.com",
                         "example.org": ".example.org"}


def test_render_and_body_round_trip():
    acl = D.render_acl([".b.com", "a.com", "x.b.com"], "andy", "now")
    assert acl.startswith(D.HEADER + "\n# Applied by andy at now\n")
    assert D.acl_body(acl) == ["a.com", ".b.com"]
    assert D.diff(acl, D.render_acl(["a.com"])) .count("-.b.com") == 1
    assert D.diff(acl, D.render_acl([".b.com", "a.com"], "someone else", "later")) == ""


def test_parent_domain():
    assert D.parent_domain("news.bbc.co.uk") == "bbc.co.uk"
    assert D.parent_domain("login.live.com") == "live.com"
    assert D.parent_domain("live.com") == "live.com"


def test_diff_ignores_order_and_shows_only_real_changes():
    old = ".windowsupdate.com\n.azure.com\nnot a domain!\n.microsoft.com\n"
    new = D.render_acl([".microsoft.com", ".azure.com", "login.live.com", ".windowsupdate.com"])
    changed = [line for line in D.diff(old, new).splitlines() if line[:1] in "+-" and line[:3] not in ("+++", "---")]
    assert sorted(changed) == ["+login.live.com", "-not a domain!"]
    assert D.same_entries(".b.com\n# x\n.a.com\n", ".a.com\n.b.com\n")
