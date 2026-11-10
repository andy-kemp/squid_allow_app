"""Runtime settings, read from environment variables.

On an installed server these come from /etc/pawpilot/pawpilot.env (loaded by
the systemd unit). See deploy/pawpilot.env.example for every option.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _bool(value: str | None, default: bool = False) -> bool:
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _list(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip().lower() for item in value.replace(";", ",").split(",") if item.strip()]


@dataclass
class Settings:
    # Storage
    data_dir: str = "/var/lib/pawpilot"

    # Squid integration
    squid_acl: str = "/etc/squid/allowed_paw.acl"
    squid_log: str = "/var/log/squid/access.log"
    squid_service: str = "squid"
    apply_cmd: str = "sudo -n /usr/local/sbin/pawpilot-apply"
    # Only the newest part of the access log is read, to keep pages fast.
    log_max_mb: int = 32
    # Imported once into the blocked list when upgrading from the Flask version.
    legacy_hidden_list: str = "/etc/squid/hidden_domains.txt"

    # Web app
    base_url: str = "https://pawproxy.local:8443"
    session_secret: str = ""
    session_hours: int = 8

    # Entra ID
    entra_tenant_id: str = ""
    entra_client_id: str = ""
    entra_client_secret: str = ""
    entra_secret_expires: str = ""
    allowed_users: list[str] = field(default_factory=list)
    required_role: str = ""

    # Testing only: never set on a real server.
    test_mode: bool = False

    @property
    def db_path(self) -> str:
        return os.path.join(self.data_dir, "pawpilot.db")

    @property
    def staging_path(self) -> str:
        return os.path.join(self.data_dir, "staging.acl")

    @property
    def redirect_uri(self) -> str:
        return self.base_url.rstrip("/") + "/auth/callback"

    @property
    def secret_days_left(self) -> int | None:
        """Days until the Entra client secret expires, or None if unknown."""
        from datetime import date
        try:
            return (date.fromisoformat(self.entra_secret_expires[:10]) - date.today()).days
        except ValueError:
            return None

    @property
    def entra_configured(self) -> bool:
        return bool(self.entra_tenant_id and self.entra_client_id and self.entra_client_secret)

    @classmethod
    def from_env(cls) -> "Settings":
        env = os.environ.get
        s = cls()
        s.data_dir = env("PAWPILOT_DATA_DIR", s.data_dir)
        s.squid_acl = env("PAWPILOT_SQUID_ACL", s.squid_acl)
        s.squid_log = env("PAWPILOT_SQUID_LOG", s.squid_log)
        s.squid_service = env("PAWPILOT_SQUID_SERVICE", s.squid_service)
        s.apply_cmd = env("PAWPILOT_APPLY_CMD", s.apply_cmd)
        s.log_max_mb = int(env("PAWPILOT_LOG_MAX_MB", str(s.log_max_mb)))
        s.legacy_hidden_list = env("PAWPILOT_LEGACY_HIDDEN_LIST", s.legacy_hidden_list)
        s.base_url = env("PAWPILOT_BASE_URL", s.base_url)
        s.session_secret = env("PAWPILOT_SESSION_SECRET", "")
        s.session_hours = int(env("PAWPILOT_SESSION_HOURS", str(s.session_hours)))
        s.entra_tenant_id = env("PAWPILOT_ENTRA_TENANT_ID", "")
        s.entra_client_id = env("PAWPILOT_ENTRA_CLIENT_ID", "")
        s.entra_client_secret = env("PAWPILOT_ENTRA_CLIENT_SECRET", "")
        s.entra_secret_expires = env("PAWPILOT_ENTRA_SECRET_EXPIRES", "").strip()
        s.allowed_users = _list(env("PAWPILOT_ALLOWED_USERS"))
        s.required_role = env("PAWPILOT_REQUIRED_ROLE", "").strip()
        s.test_mode = _bool(env("PAWPILOT_TEST_MODE"))
        return s
