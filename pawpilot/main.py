"""PAW Proxy Pilot web application."""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import time
from contextlib import asynccontextmanager
from datetime import date
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from . import __version__, auth, domains as D, squid
from .db import Database, now, today
from .settings import Settings

HERE = Path(__file__).parent
EXPIRY_CHECK_SECONDS = 300
IMPORT_LIMIT = 2000


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    os.makedirs(settings.data_dir, exist_ok=True)
    db = Database(settings.db_path)

    secret = settings.session_secret
    if not secret:
        if not settings.test_mode:
            raise RuntimeError("PAWPILOT_SESSION_SECRET is not set. Run the installer or set it in pawpilot.env.")
        secret = secrets.token_urlsafe(32)

    # ------------------------------------------------------------------ domain state
    def active_allowed() -> list[dict[str, Any]]:
        """Allowed rows that have not expired; only these reach Squid."""
        day = today()
        return [r for r in db.list_domains("allow") if not r["expires_on"] or r["expires_on"] >= day]

    def build_acl(user: str = "") -> str:
        return D.render_acl([r["entry"] for r in active_allowed()], generated_by=user,
                            generated_at=now() if user else "")

    def pending_changes() -> bool:
        return not D.same_entries(build_acl(), squid.live_acl(settings))

    def rows_in(acl: str, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """The rows an ACL actually represents (its entries plus ones a wider entry covers)."""
        matcher = D.Matcher(D.acl_body(acl))
        return [r for r in rows if matcher.match(r["entry"].lstrip("."))]

    def do_apply(upn: str, acl: str, note: str) -> squid.Result:
        result = squid.apply(settings, acl)
        if result.ok:
            version = db.add_version(acl, upn, note, rows_in(acl, db.list_domains("allow")))
            db.audit(upn, "apply", f"Version {version}: {note}".strip(": "))
        else:
            db.audit(upn, "apply-failed", result.output)
        return result

    def expire_due() -> list[str]:
        """Remove allowed entries past their expiry date and take them out of the live list.

        Only the expired entries are removed from the live list, so other staged
        changes are not published without someone reviewing them.
        """
        rows = db.expired()
        if not rows:
            return []
        gone = {r["entry"] for r in rows}
        db.delete_domains([r["id"] for r in rows], "allow")
        for r in rows:
            db.audit("system", "allow-expired", f"{r['entry']} (expired {r['expires_on']})")
        live = D.acl_body(squid.live_acl(settings))
        remaining = [e for e in live if e not in gone]
        if remaining != live:
            do_apply("system", D.render_acl(remaining, "system", now()),
                     "Expired: " + ", ".join(sorted(gone))[:180])
        return sorted(gone)

    def seed() -> None:
        """First start: take over the existing Squid allow list (and the old hidden list)."""
        if db.meta("seeded"):
            return
        counts = {"allow": 0, "block": 0}
        sources = (("allow", squid.live_acl(settings)), ("block", _read(settings.legacy_hidden_list)))
        for kind, text in sources:
            for line in D.acl_body(text):
                try:
                    entry = D.normalise(line)
                except D.DomainError:
                    continue
                if not db.find_domain(entry) and db.put_domain(entry, kind, "import", "Imported at first start"):
                    counts[kind] += 1
        db.set_meta("seeded", now())
        if counts["allow"] or counts["block"]:
            db.audit("system", "import", f"{counts['allow']} allowed and {counts['block']} blocked entries imported")

    seed()

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        async def loop() -> None:
            while True:
                try:
                    await asyncio.to_thread(expire_due)
                except Exception:  # noqa: BLE001 - keep the loop alive whatever happens
                    pass
                await asyncio.sleep(EXPIRY_CHECK_SECONDS)

        task = asyncio.create_task(loop()) if not settings.test_mode else None
        yield
        if task:
            task.cancel()

    app = FastAPI(title="PAW Proxy Pilot", version=__version__, docs_url=None, redoc_url=None,
                  openapi_url=None, lifespan=lifespan)
    app.add_middleware(
        SessionMiddleware,
        secret_key=secret,
        session_cookie="pawpilot_session",
        max_age=settings.session_hours * 3600,
        same_site="lax",
        https_only=not settings.test_mode,
    )
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
    templates = Jinja2Templates(directory=HERE / "templates")
    templates.env.globals.update(version=__version__, today=today)
    templates.env.filters["stamp"] = squid.stamp
    app.state.settings = settings
    app.state.db = db
    app.state.expire_due = expire_due

    # ------------------------------------------------------------------ helpers
    def current_user(request: Request) -> dict[str, Any] | None:
        user = request.session.get("user")
        if not user:
            return None
        if time.time() - user.get("signed_in", 0) > settings.session_hours * 3600:
            request.session.clear()
            return None
        return user

    def require_user(request: Request) -> dict[str, Any]:
        user = current_user(request)
        if not user:
            raise HTTPException(status_code=303, headers={"Location": "/login"})
        return user

    def check_csrf(request: Request, token: str) -> dict[str, Any]:
        user = require_user(request)
        if not token or not secrets.compare_digest(token, user.get("csrf", "")):
            raise HTTPException(status_code=400, detail="Form expired. Go back, refresh the page and try again.")
        return user

    def flash(request: Request, message: str, level: str = "ok") -> None:
        # Reassign rather than append in place, so the session notices the change and is saved.
        request.session["flash"] = [*request.session.get("flash", []), {"message": message, "level": level}]

    def render(request: Request, name: str, **ctx: Any) -> HTMLResponse:
        ctx.setdefault("user", current_user(request))
        ctx["flashes"] = request.session.pop("flash", [])
        ctx["pending"] = pending_changes() if ctx["user"] else False
        ctx["secret_days"] = settings.secret_days_left if ctx["user"] else None
        return templates.TemplateResponse(request, name, ctx)

    def back(request: Request, path: str) -> RedirectResponse:
        return RedirectResponse(path, status_code=303)

    def parse_expiry(value: str) -> str:
        value = (value or "").strip()
        if not value:
            return ""
        try:
            day = date.fromisoformat(value)
        except ValueError:
            raise D.DomainError("The expiry date must look like 2026-12-31.") from None
        if day.isoformat() < today():
            raise D.DomainError("The expiry date is in the past.")
        return day.isoformat()

    def allow(user: dict[str, Any], raw: str, subdomains: bool | None, note: str = "",
              expires_on: str = "") -> tuple[str, str]:
        """Add one allowed entry. Returns (level, message) for the flash."""
        entry = D.normalise(raw, subdomains)
        wider = D.Matcher(r["entry"] for r in active_allowed()).covering(entry)
        if wider:
            return "warn", f"{entry} is already allowed by {wider}."
        if not db.put_domain(entry, "allow", user["upn"], note.strip()[:200], expires_on):
            return "warn", f"{entry} is already on the allow list."
        db.audit(user["upn"], "allow-add", " ".join(filter(None, [entry, note.strip()[:200],
                                                         f"expires {expires_on}" if expires_on else ""])))
        return "ok", f"{entry} allowed. Review and apply to make it live."

    def block(user: dict[str, Any], raw: str, subdomains: bool | None) -> tuple[str, str]:
        entry = D.normalise(raw, subdomains)
        existing = db.find_domain(entry)
        if not db.put_domain(entry, "block", user["upn"]):
            return "warn", f"{entry} is already on the blocked list."
        db.audit(user["upn"], "block-add", entry)
        if existing and existing["list"] == "allow":
            return "ok", f"{entry} moved from allowed to blocked. Review and apply to make it live."
        return "ok", f"{entry} confirmed as blocked."

    def unsorted_hosts() -> tuple[list[dict[str, Any]], squid.LogSummary]:
        summary = squid.read_log(settings)
        allowed = D.Matcher(r["entry"] for r in active_allowed())
        blocked = D.Matcher(r["entry"] for r in db.list_domains("block"))
        hosts = []
        for host, info in summary.denied.items():
            if allowed.match(host) or blocked.match(host):
                continue
            clients = sorted(info["clients"])
            hosts.append({"host": host, "parent": D.parent_domain(host), "count": info["count"],
                          "last": info["last"], "clients": clients[:3], "more_clients": max(0, len(clients) - 3)})
        hosts.sort(key=lambda h: (-h["last"], h["host"]))
        return hosts, summary

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException) -> Response:
        if exc.status_code == 303:
            return RedirectResponse(exc.headers["Location"], status_code=303)
        response = render(request, "error.html", status=exc.status_code, detail=exc.detail)
        response.status_code = exc.status_code
        return response

    # ------------------------------------------------------------------ auth
    @app.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request):
        if current_user(request):
            return RedirectResponse("/", status_code=303)
        return render(request, "login.html", configured=settings.entra_configured)

    @app.get("/login/start")
    async def login_start(request: Request):
        if not settings.entra_configured:
            raise HTTPException(status_code=500, detail="Entra ID is not configured in pawpilot.env.")
        flow = auth.begin(settings)
        auth_uri = flow.pop("auth_uri")
        request.session["flow"] = flow
        return RedirectResponse(auth_uri, status_code=303)

    @app.get("/auth/callback")
    async def auth_callback(request: Request):
        flow = request.session.pop("flow", None)
        if not flow:
            flash(request, "Sign-in expired. Please try again.", "warn")
            return RedirectResponse("/login", status_code=303)
        try:
            user = auth.complete(settings, flow, dict(request.query_params))
        except (auth.AuthError, ValueError) as exc:
            db.audit("-", "sign-in-denied", str(exc))
            return render(request, "login.html", configured=True, error=str(exc), user=None)
        request.session.clear()
        request.session["user"] = user
        db.audit(user["upn"], "sign-in", request.client.host if request.client else "")
        return RedirectResponse("/", status_code=303)

    @app.post("/logout")
    async def logout(request: Request, csrf: str = Form("")):
        user = check_csrf(request, csrf)
        db.audit(user["upn"], "sign-out")
        request.session.clear()
        return RedirectResponse("/login", status_code=303)

    # ------------------------------------------------------------------ overview
    @app.get("/healthz", response_class=PlainTextResponse)
    async def healthz():
        return "ok"

    @app.get("/", response_class=HTMLResponse)
    async def overview(request: Request):
        require_user(request)
        hosts, summary = unsorted_hosts()
        clients = sorted(({"ip": ip, **info} for ip, info in summary.clients.items()),
                         key=lambda c: -c["last"])[:100]
        soon = sorted((r for r in active_allowed() if r["expires_on"]), key=lambda r: r["expires_on"])[:5]
        return render(request, "overview.html", allowed_count=len(active_allowed()),
                      blocked_count=len(db.list_domains("block")), unsorted_count=len(hosts),
                      top=sorted(hosts, key=lambda h: -h["count"])[:5], clients=clients, soon=soon,
                      summary=summary, squid_state=squid.service_state(settings))

    # ------------------------------------------------------------------ allowed
    @app.get("/allowed", response_class=HTMLResponse)
    async def allowed_page(request: Request):
        require_user(request)
        rows = db.list_domains("allow")
        _, redundant = D.effective(r["entry"] for r in rows)
        day = today()
        for r in rows:
            r["covered_by"] = redundant.get(r["entry"], "")
            r["expired"] = bool(r["expires_on"]) and r["expires_on"] < day
        rows.sort(key=lambda r: D.sort_key(r["entry"]))
        return render(request, "allowed.html", rows=rows)

    @app.post("/allowed/add")
    async def allowed_add(request: Request, csrf: str = Form(""), domain: str = Form(""),
                          subdomains: str = Form(""), note: str = Form(""), expires_on: str = Form("")):
        user = check_csrf(request, csrf)
        try:
            # Ticked means "with subdomains"; unticked keeps a leading dot or *. if one was typed.
            level, message = allow(user, domain, True if subdomains else None, note, parse_expiry(expires_on))
        except D.DomainError as exc:
            level, message = "error", str(exc)
        flash(request, message, level)
        return back(request, "/allowed")

    @app.post("/allowed/import")
    async def allowed_import(request: Request, csrf: str = Form(""), entries: str = Form("")):
        user = check_csrf(request, csrf)
        lines = [ln.split("#", 1)[0].strip() for ln in entries.splitlines()]
        lines = [ln for ln in lines if ln][:IMPORT_LIMIT]
        added, skipped, bad = 0, 0, []
        for line in lines:
            try:
                level, _ = allow(user, line, None, "Imported")
            except D.DomainError:
                bad.append(line[:60])
                continue
            added += level == "ok"
            skipped += level != "ok"
        parts = [f"{added} added"]
        if skipped:
            parts.append(f"{skipped} already allowed")
        if bad:
            parts.append(f"{len(bad)} not valid: " + ", ".join(bad[:10]) + ("…" if len(bad) > 10 else ""))
        flash(request, "Import: " + "; ".join(parts) + ("." if not bad else ""),
              "warn" if bad else "ok")
        return back(request, "/allowed")

    @app.get("/allowed/export", response_class=PlainTextResponse)
    async def allowed_export(request: Request):
        require_user(request)
        rows = sorted(active_allowed(), key=lambda r: D.sort_key(r["entry"]))
        body = "".join(r["entry"] + (f"  # {r['note']}" if r["note"] else "") + "\n" for r in rows)
        return PlainTextResponse(body, headers={
            "Content-Disposition": f'attachment; filename="paw-allow-list-{today()}.txt"'})

    @app.get("/allowed/{domain_id}/edit", response_class=HTMLResponse)
    async def allowed_edit(request: Request, domain_id: int):
        require_user(request)
        row = db.get_domain(domain_id)
        if not row or row["list"] != "allow":
            raise HTTPException(status_code=404, detail="That domain is no longer on the allow list.")
        return render(request, "allowed_edit.html", row=row, error="")

    @app.post("/allowed/{domain_id}/edit")
    async def allowed_update(request: Request, domain_id: int, csrf: str = Form(""), note: str = Form(""),
                             expires_on: str = Form("")):
        user = check_csrf(request, csrf)
        row = db.get_domain(domain_id)
        if not row or row["list"] != "allow":
            raise HTTPException(status_code=404, detail="That domain is no longer on the allow list.")
        try:
            expiry = parse_expiry(expires_on)
        except D.DomainError as exc:
            return render(request, "allowed_edit.html", row={**row, "note": note, "expires_on": expires_on},
                          error=str(exc))
        db.update_domain(domain_id, note.strip()[:200], expiry)
        db.audit(user["upn"], "allow-edit", f"{row['entry']}: note '{note.strip()[:200]}', "
                                              f"expires {expiry or 'never'}")
        flash(request, f"{row['entry']} updated.")
        return back(request, "/allowed")

    @app.post("/allowed/delete")
    async def allowed_delete(request: Request):
        form = await request.form()
        user = check_csrf(request, str(form.get("csrf", "")))
        removed = db.delete_domains(_ints(form.getlist("ids")), "allow")
        for entry in removed:
            db.audit(user["upn"], "allow-remove", entry)
        if removed:
            flash(request, f"Removed {_count(removed, 'domain')} from the allow list. Review and apply to make it live.")
        else:
            flash(request, "Nothing was selected.", "warn")
        return back(request, "/allowed")

    # ------------------------------------------------------------------ blocked
    @app.get("/blocked", response_class=HTMLResponse)
    async def blocked_page(request: Request):
        require_user(request)
        rows = sorted(db.list_domains("block"), key=lambda r: D.sort_key(r["entry"]))
        return render(request, "blocked.html", rows=rows)

    @app.post("/blocked/add")
    async def blocked_add(request: Request, csrf: str = Form(""), domain: str = Form(""),
                          subdomains: str = Form("")):
        user = check_csrf(request, csrf)
        try:
            level, message = block(user, domain, True if subdomains else None)
        except D.DomainError as exc:
            level, message = "error", str(exc)
        flash(request, message, level)
        return back(request, "/blocked")

    @app.post("/blocked/delete")
    async def blocked_delete(request: Request):
        form = await request.form()
        user = check_csrf(request, str(form.get("csrf", "")))
        removed = db.delete_domains(_ints(form.getlist("ids")), "block")
        for entry in removed:
            db.audit(user["upn"], "block-remove", entry)
        if removed:
            flash(request, f"Removed {_count(removed, 'domain')} from the blocked list. "
                           "If PAWs request them again they'll show up under Unsorted.")
        else:
            flash(request, "Nothing was selected.", "warn")
        return back(request, "/blocked")

    # ------------------------------------------------------------------ unsorted
    @app.get("/unsorted", response_class=HTMLResponse)
    async def unsorted_page(request: Request):
        require_user(request)
        hosts, summary = unsorted_hosts()
        return render(request, "unsorted.html", hosts=hosts, summary=summary)

    @app.post("/unsorted/sort")
    async def unsorted_sort(request: Request):
        """Allow or block one or many hosts from the Unsorted page.

        action is allow-host (exact hosts), allow-domain (the registrable domain
        and its subdomains) or block (the registrable domain and its subdomains).
        """
        form = await request.form()
        user = check_csrf(request, str(form.get("csrf", "")))
        action = str(form.get("action", ""))
        hosts = [str(h) for h in form.getlist("hosts")][:IMPORT_LIMIT]
        if action not in {"allow-host", "allow-domain", "block"} or not hosts:
            flash(request, "Nothing was selected.", "warn")
            return back(request, "/unsorted")
        done, problems = [], []
        for raw in hosts:
            try:
                host = D.normalise(raw, False)
                if action == "allow-host":
                    level, message = allow(user, host, False)
                elif action == "allow-domain":
                    level, message = allow(user, D.parent_domain(host), True)
                else:
                    level, message = block(user, D.parent_domain(host), True)
            except D.DomainError as exc:
                level, message = "error", str(exc)
            (done if level == "ok" else problems).append(message)
        if len(done) == 1 and not problems:
            flash(request, done[0])
        elif done:
            verb = "blocked" if action == "block" else "allowed"
            tail = " Review and apply to make it live." if action != "block" else ""
            flash(request, f"{_count(done, 'entry', 'entries')} {verb}.{tail}")
        for message in problems[:5]:
            flash(request, message, "warn")
        return back(request, "/unsorted")

    # ------------------------------------------------------------------ changes
    @app.get("/changes", response_class=HTMLResponse)
    async def changes(request: Request):
        require_user(request)
        acl = build_acl()
        live = squid.live_acl(settings)
        _, redundant = D.effective(r["entry"] for r in active_allowed())
        return render(request, "changes.html", acl=acl, diff=D.diff(live, acl), has_live=bool(live),
                      managed=live.startswith(D.HEADER), count=len(D.acl_body(acl)), redundant=redundant)

    @app.post("/apply")
    async def apply_changes(request: Request, csrf: str = Form(""), note: str = Form("")):
        user = check_csrf(request, csrf)
        result = do_apply(user["upn"], build_acl(user["upn"]), note.strip()[:200])
        if result.ok:
            flash(request, "Applied. Squid reloaded the allow list without dropping connections.")
            return RedirectResponse("/", status_code=303)
        flash(request, "Not applied. The live allow list has not changed:\n" + result.output, "error")
        return RedirectResponse("/changes", status_code=303)

    # ------------------------------------------------------------------ history
    @app.get("/history", response_class=HTMLResponse)
    async def history(request: Request):
        require_user(request)
        return render(request, "history.html", versions=db.list_versions())

    @app.get("/history/{version_id}", response_class=HTMLResponse)
    async def history_view(request: Request, version_id: int):
        require_user(request)
        version = db.get_version(version_id)
        if not version:
            raise HTTPException(status_code=404, detail="Version not found.")
        live = squid.live_acl(settings)
        return render(request, "version.html", ver=version,  # "version" is the app version in templates
                      diff=D.diff(live, version["acl"], "live", f"version {version_id}"))

    @app.post("/history/{version_id}/restore")
    async def history_restore(request: Request, version_id: int, csrf: str = Form("")):
        user = check_csrf(request, csrf)
        version = db.get_version(version_id)
        if not version:
            raise HTTPException(status_code=404, detail="Version not found.")
        previous = db.list_domains("allow")
        db.replace_allowed(json.loads(version["snapshot"] or "[]"))
        result = do_apply(user["upn"], build_acl(user["upn"]), f"Restored version {version_id}")
        if result.ok:
            flash(request, f"Restored version {version_id} and applied it.")
            return RedirectResponse("/", status_code=303)
        db.replace_allowed(previous)
        flash(request, f"Could not restore version {version_id}; nothing changed:\n{result.output}", "error")
        return RedirectResponse("/history", status_code=303)

    # ------------------------------------------------------------------ audit, settings
    @app.get("/audit", response_class=HTMLResponse)
    async def audit_page(request: Request):
        require_user(request)
        return render(request, "audit.html", entries=db.list_audit())

    @app.get("/settings", response_class=HTMLResponse)
    async def settings_page(request: Request):
        require_user(request)
        return render(request, "settings.html", env=settings, squid_state=squid.service_state(settings),
                      summary=squid.read_log(settings))

    return app


def _read(path: str) -> str:
    try:
        with open(path) as fh:
            return fh.read()
    except OSError:
        return ""


def _ints(values: list[Any]) -> list[int]:
    out = []
    for value in values:
        try:
            out.append(int(value))
        except (TypeError, ValueError):
            pass
    return out


def _count(items: list[Any], singular: str, plural: str | None = None) -> str:
    n = len(items)
    return f"{n} {singular if n == 1 else (plural or singular + 's')}"


def run() -> None:
    import uvicorn

    host = os.environ.get("PAWPILOT_LISTEN", "0.0.0.0")
    port = int(os.environ.get("PAWPILOT_PORT", "8443"))
    cert = os.environ.get("PAWPILOT_TLS_CERT", "/etc/pawpilot/tls/pawpilot.crt")
    key = os.environ.get("PAWPILOT_TLS_KEY", "/etc/pawpilot/tls/pawpilot.key")
    uvicorn.run(create_app(), host=host, port=port, ssl_certfile=cert, ssl_keyfile=key,
                proxy_headers=False, server_header=False)


if __name__ == "__main__":
    run()
