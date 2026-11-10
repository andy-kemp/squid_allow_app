import re
from datetime import date, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from pawpilot import auth, domains as D
from pawpilot.main import create_app

CLAIMS = {"tid": "tenant-1", "preferred_username": "admin@example.com", "name": "Admin User",
          "oid": "o1", "roles": ["PAWProxyPilot.Admin"]}


@pytest.fixture
def client(settings, monkeypatch):
    monkeypatch.setattr(auth, "begin", lambda s: {"auth_uri": "https://login.example/authorize", "state": "x"})
    monkeypatch.setattr(auth, "complete", lambda s, flow, q: auth.authorise(s, CLAIMS))
    return TestClient(create_app(settings), follow_redirects=False)


def sign_in(client):
    r = client.get("/login/start")
    assert r.status_code == 303 and r.headers["location"].startswith("https://login.example")
    r = client.get("/auth/callback?code=abc&state=x")
    assert r.status_code == 303 and r.headers["location"] == "/"
    return re.search(r'name="csrf" value="([^"]+)"', client.get("/").text).group(1)


def live(settings):
    return D.acl_body(Path(settings.squid_acl).read_text())


def allowed(client):
    return {r["entry"]: r for r in client.app.state.db.list_domains("allow")}


def test_requires_sign_in(client):
    for path in ("/", "/allowed", "/blocked", "/unsorted", "/changes", "/history", "/audit", "/settings",
                 "/allowed/export"):
        r = client.get(path)
        assert r.status_code == 303 and r.headers["location"] == "/login", path
    assert "Sign in with Microsoft" in client.get("/login").text
    assert client.post("/allowed/add", data={"domain": "evil.com"}).status_code == 303
    assert "evil.com" not in allowed(client)


def test_authorise_rules(settings):
    with pytest.raises(auth.AuthError):
        auth.authorise(settings, {**CLAIMS, "tid": "other"})
    with pytest.raises(auth.AuthError):
        auth.authorise(settings, {**CLAIMS, "roles": []})
    settings.required_role = ""
    with pytest.raises(auth.AuthError):  # nothing configured -> nobody gets in
        auth.authorise(settings, CLAIMS)
    settings.allowed_users = ["admin@example.com"]
    assert auth.authorise(settings, CLAIMS)["upn"] == "admin@example.com"


def test_refuses_to_start_without_session_secret(settings):
    settings.session_secret = ""
    settings.test_mode = False
    with pytest.raises(RuntimeError):
        create_app(settings)


def test_first_start_imports_existing_lists(client):
    db = client.app.state.db
    assert set(allowed(client)) == {".microsoft.com", ".windowsupdate.com"}  # the invalid line is skipped
    assert [r["entry"] for r in db.list_domains("block")] == [".doubleclick.net"]
    sign_in(client)
    # The junk line in the old file is the only difference waiting to be applied.
    assert "Review and apply" in client.get("/").text
    assert "-not a domain!" in client.get("/changes").text and "+." not in client.get("/changes").text


def test_order_and_comments_alone_are_not_a_change(client, settings):
    Path(settings.squid_acl).write_text("# old header\n.windowsupdate.com\n\n.microsoft.com\n")
    sign_in(client)
    assert "Review and apply" not in client.get("/").text
    assert "No differences" in client.get("/changes").text


def test_apply_that_does_not_change_the_live_list_is_reported(client, settings, tmp_path):
    csrf = sign_in(client)
    client.post("/allowed/add", data={"csrf": csrf, "domain": "github.com"})
    helper = tmp_path / "noop.sh"
    helper.write_text("#!/bin/sh\necho pretending\n")
    helper.chmod(0o755)
    settings.apply_cmd = str(helper)
    assert client.post("/apply", data={"csrf": csrf}).headers["location"] == "/changes"
    assert "doesn't match what was sent" in client.get("/changes").text.replace("&#39;", "'")
    assert client.app.state.db.list_versions() == []


def test_csrf_enforced(client):
    sign_in(client)
    for path in ("/allowed/add", "/allowed/delete", "/allowed/import", "/blocked/add", "/blocked/delete",
                 "/unsorted/sort", "/apply", "/history/1/restore", "/logout"):
        assert client.post(path, data={"domain": "x.com", "csrf": "wrong"}).status_code == 400, path
    assert "x.com" not in allowed(client)


def test_all_pages_render(client):
    sign_in(client)
    for path in ("/", "/allowed", "/blocked", "/unsorted", "/changes", "/history", "/audit", "/settings"):
        r = client.get(path)
        assert r.status_code == 200 and "<small>v2." in r.text, path
    assert client.get("/history/99").status_code == 404
    assert client.get("/allowed/999/edit").status_code == 404


def test_unsorted_comes_from_denied_log_lines(client):
    sign_in(client)
    page = client.get("/unsorted").text
    for host in ("login.live.com", "news.bbc.co.uk", "ads.tracker.example.org"):
        assert host in page
    assert "graph.microsoft.com" not in page  # allowed and not denied
    assert "203.0.113.9" not in page          # raw IPs are not offered
    assert "Allow .bbc.co.uk" in page
    row = re.search(r"login\.live\.com</td>\s*<td class=\"right\">(\d+)</td>", page)
    assert row and row.group(1) == "2"


def test_add_review_apply_restore(client, settings):
    csrf = sign_in(client)
    r = client.post("/allowed/add", data={"csrf": csrf, "domain": "https://Portal.Azure.com/x", "note": "Portal"})
    assert r.status_code == 303
    assert allowed(client)["portal.azure.com"]["note"] == "Portal"
    assert "portal.azure.com" not in live(settings)  # staged only
    assert "Review and apply" in client.get("/").text

    changes = client.get("/changes").text
    assert "+portal.azure.com" in changes

    r = client.post("/apply", data={"csrf": csrf, "note": "first"})
    assert r.status_code == 303 and r.headers["location"] == "/"
    assert live(settings) == [".microsoft.com", "portal.azure.com", ".windowsupdate.com"]
    assert Path(settings.squid_acl).read_text().startswith(D.HEADER)
    assert "Review and apply" not in client.get("/").text

    # A second change, then roll back to version 1.
    client.post("/allowed/add", data={"csrf": csrf, "domain": "github.com", "subdomains": "1"})
    client.post("/apply", data={"csrf": csrf, "note": "github"})
    assert ".github.com" in live(settings)
    page = client.get("/history/1")
    assert page.status_code == 200 and "<small>v2." in page.text and "-.github.com" in page.text
    r = client.post("/history/1/restore", data={"csrf": csrf})
    assert r.status_code == 303
    assert ".github.com" not in live(settings) and ".github.com" not in allowed(client)
    assert allowed(client)["portal.azure.com"]["note"] == "Portal"

    audit = client.get("/audit").text
    for action in ("sign-in", "allow-add", "apply", "import"):
        assert action in audit
    assert "admin@example.com" in audit


def test_failed_apply_changes_nothing(client, settings, tmp_path):
    csrf = sign_in(client)
    client.post("/allowed/add", data={"csrf": csrf, "domain": "github.com"})
    (tmp_path / "fail").write_text("")
    r = client.post("/apply", data={"csrf": csrf})
    assert r.headers["location"] == "/changes"
    assert "squid said no" in client.get("/changes").text
    assert "github.com" not in live(settings)
    assert client.app.state.db.list_versions() == []
    assert "apply-failed" in client.get("/audit").text


def test_invalid_and_duplicate_domains(client):
    csrf = sign_in(client)
    before = set(allowed(client))
    for bad in ("not a domain", "10.1.2.3", 'x.com\n.evil.com', "localhost"):
        client.post("/allowed/add", data={"csrf": csrf, "domain": bad})
        assert "valid domain name" in client.get("/allowed").text, bad
    client.post("/allowed/add", data={"csrf": csrf, "domain": "graph.microsoft.com"})
    assert "already allowed by .microsoft.com" in client.get("/allowed").text
    assert set(allowed(client)) == before
    client.post("/allowed/add", data={"csrf": csrf, "domain": "example.com", "expires_on": "2001-01-01"})
    assert "in the past" in client.get("/allowed").text
    assert set(allowed(client)) == before


def test_wider_entry_makes_narrow_one_redundant(client, settings):
    csrf = sign_in(client)
    client.post("/allowed/add", data={"csrf": csrf, "domain": "api.github.com"})
    client.post("/allowed/add", data={"csrf": csrf, "domain": "github.com", "subdomains": "1"})
    assert "covered by .github.com" in client.get("/allowed").text
    client.post("/apply", data={"csrf": csrf})
    assert ".github.com" in live(settings) and "api.github.com" not in live(settings)


def test_sort_unsorted_hosts(client, settings):
    csrf = sign_in(client)
    client.post("/unsorted/sort", data={"csrf": csrf, "action": "allow-host", "hosts": "login.live.com"})
    client.post("/unsorted/sort", data={"csrf": csrf, "action": "allow-domain", "hosts": "news.bbc.co.uk"})
    client.post("/unsorted/sort", data={"csrf": csrf, "action": "block", "hosts": "ads.tracker.example.org"})
    assert {"login.live.com", ".bbc.co.uk"} <= set(allowed(client))
    assert ".example.org" in [r["entry"] for r in client.app.state.db.list_domains("block")]
    assert "Nothing to sort" in client.get("/unsorted").text
    # bulk, with junk mixed in
    client.post("/blocked/delete", data={"csrf": csrf, "ids": [r["id"] for r in client.app.state.db.list_domains("block")]})
    r = client.post("/unsorted/sort", data={"csrf": csrf, "action": "allow-host",
                                            "hosts": ["ads.tracker.example.org", "bad host"]})
    assert r.status_code == 303 and "ads.tracker.example.org" in allowed(client)
    assert client.post("/unsorted/sort", data={"csrf": csrf, "action": "nonsense", "hosts": "a.com"}).status_code == 303
    assert "a.com" not in allowed(client)


def test_remove_edit_import_export(client):
    csrf = sign_in(client)
    r = client.post("/allowed/import", data={"csrf": csrf, "entries":
                    "# comment\n.github.com  # code\n*.example.org\nportal.azure.com\nnot valid!\n.microsoft.com\n"})
    assert r.status_code == 303
    page = client.get("/allowed").text
    assert "3 added" in page and "1 already allowed" in page and "1 not valid" in page
    rows = allowed(client)
    assert {".github.com", ".example.org", "portal.azure.com"} <= set(rows)

    future = (date.today() + timedelta(days=30)).isoformat()
    rid = rows["portal.azure.com"]["id"]
    assert client.get(f"/allowed/{rid}/edit").status_code == 200
    client.post(f"/allowed/{rid}/edit", data={"csrf": csrf, "note": "Break glass", "expires_on": future})
    assert allowed(client)["portal.azure.com"]["expires_on"] == future
    r = client.post(f"/allowed/{rid}/edit", data={"csrf": csrf, "note": "x", "expires_on": "nope"})
    assert r.status_code == 200 and "must look like" in r.text

    export = client.get("/allowed/export")
    assert "attachment" in export.headers["content-disposition"]
    assert "portal.azure.com  # Break glass\n" in export.text and ".github.com  # Imported\n" in export.text

    client.post("/allowed/delete", data={"csrf": csrf, "ids": [rows[".github.com"]["id"], rows[".example.org"]["id"], "junk"]})
    assert not {".github.com", ".example.org"} & set(allowed(client))
    # ids from the other list are ignored
    blocked_id = client.app.state.db.list_domains("block")[0]["id"]
    client.post("/allowed/delete", data={"csrf": csrf, "ids": blocked_id})
    assert len(client.app.state.db.list_domains("block")) == 1


def test_blocked_list(client):
    csrf = sign_in(client)
    client.post("/blocked/add", data={"csrf": csrf, "domain": "facebook.com", "subdomains": "1"})
    client.post("/blocked/add", data={"csrf": csrf, "domain": "windowsupdate.com", "subdomains": "1"})
    blocked = {r["entry"]: r["id"] for r in client.app.state.db.list_domains("block")}
    assert {".facebook.com", ".windowsupdate.com"} <= set(blocked)
    assert ".windowsupdate.com" not in allowed(client)  # moved off the allow list
    client.post("/blocked/delete", data={"csrf": csrf, "ids": blocked[".facebook.com"]})
    assert ".facebook.com" not in [r["entry"] for r in client.app.state.db.list_domains("block")]


def test_expired_domains_are_removed_without_publishing_staged_changes(client, settings):
    csrf = sign_in(client)
    db = client.app.state.db
    db.put_domain("temp.example.com", "allow", "andy", "temporary", "2999-01-01")
    client.post("/apply", data={"csrf": csrf})
    assert "temp.example.com" in live(settings)

    client.post("/allowed/add", data={"csrf": csrf, "domain": "staged.example.net"})  # staged, not applied
    row = db.find_domain("temp.example.com")
    db.update_domain(row["id"], row["note"], "2000-01-01")
    assert "temp.example.com" not in D.acl_body(client.get("/allowed/export").text)

    assert client.app.state.expire_due() == ["temp.example.com"]
    assert "temp.example.com" not in live(settings)
    assert "staged.example.net" not in live(settings)      # still waiting for review
    assert "staged.example.net" in allowed(client)
    assert db.list_versions()[0]["user"] == "system"
    assert client.app.state.expire_due() == []
    assert "allow-expired" in client.get("/audit").text


def test_secret_expiry_banner(client, settings):
    settings.entra_secret_expires = (date.today() + timedelta(days=5)).isoformat()
    sign_in(client)
    assert "expires in 5 days" in client.get("/").text
    settings.entra_secret_expires = (date.today() + timedelta(days=200)).isoformat()
    assert "expires in" not in client.get("/").text


def test_sign_out(client):
    csrf = sign_in(client)
    assert client.post("/logout", data={"csrf": csrf}).headers["location"] == "/login"
    assert client.get("/").headers["location"] == "/login"
