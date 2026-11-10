"""Entra ID sign-in (OpenID Connect authorization code flow with PKCE, via MSAL)."""

from __future__ import annotations

import secrets
import time
from typing import Any

import msal

from .settings import Settings


class AuthError(Exception):
    pass


def _app(settings: Settings) -> msal.ConfidentialClientApplication:
    return msal.ConfidentialClientApplication(
        client_id=settings.entra_client_id,
        client_credential=settings.entra_client_secret,
        authority=f"https://login.microsoftonline.com/{settings.entra_tenant_id}",
    )


def begin(settings: Settings) -> dict[str, Any]:
    """Start sign-in. Returns the MSAL flow (store in the session) incl. auth_uri."""
    return _app(settings).initiate_auth_code_flow(
        scopes=[], redirect_uri=settings.redirect_uri, prompt="select_account",
    )


def complete(settings: Settings, flow: dict[str, Any], query: dict[str, str]) -> dict[str, Any]:
    """Finish sign-in and return the signed-in user, or raise AuthError."""
    result = _app(settings).acquire_token_by_auth_code_flow(flow, query)
    if "error" in result:
        raise AuthError(result.get("error_description") or result["error"])
    claims = result.get("id_token_claims") or {}
    return authorise(settings, claims)


def authorise(settings: Settings, claims: dict[str, Any]) -> dict[str, Any]:
    """Check the token claims against the tenant, role and allow-list."""
    if claims.get("tid") != settings.entra_tenant_id:
        raise AuthError("This account is not from the permitted tenant.")
    upn = (claims.get("preferred_username") or claims.get("upn") or claims.get("email") or "").lower()
    roles = claims.get("roles") or []
    if settings.required_role and settings.required_role not in roles:
        raise AuthError(f"Your account does not have the '{settings.required_role}' app role for PAW Proxy Pilot.")
    if settings.allowed_users and upn not in settings.allowed_users:
        raise AuthError(f"{upn or 'This account'} is not on the PAW Proxy Pilot allow-list.")
    if not settings.required_role and not settings.allowed_users:
        raise AuthError("PAW Proxy Pilot has no app role or allow-list configured, so nobody can sign in.")
    return {
        "name": claims.get("name") or upn,
        "upn": upn,
        "oid": claims.get("oid", ""),
        "signed_in": int(time.time()),
        "csrf": secrets.token_urlsafe(32),
    }
