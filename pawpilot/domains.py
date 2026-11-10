"""Domain entries: validation, matching and rendering the Squid ACL file.

An entry is either an exact host (``graph.microsoft.com``) or a domain with all
of its subdomains, written Squid-style with a leading dot (``.microsoft.com``).
Entries are validated strictly because they are written into a file Squid loads.
"""

from __future__ import annotations

import difflib
import re
from typing import Iterable

HEADER = "# Managed by PAW Proxy Pilot. Edits made here are overwritten; use the web interface."
_LABEL = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")


class DomainError(ValueError):
    pass


def clean_host(raw: str) -> str:
    """Reduce whatever was typed or logged (URL, host:port) to a bare lowercase hostname."""
    value = (raw or "").strip().lower()
    if "://" in value:
        value = value.split("://", 1)[1]
    value = value.split("/", 1)[0].split("?", 1)[0]
    if "@" in value:
        value = value.rsplit("@", 1)[1]
    if value.count(":") == 1:
        value = value.split(":", 1)[0]
    return value.rstrip(".")


def is_hostname(host: str) -> bool:
    if not host or len(host) > 253 or "." not in host:
        return False
    labels = host.split(".")
    if not all(_LABEL.fullmatch(label) for label in labels):
        return False
    return not labels[-1].isdigit()  # rules out IPv4 addresses


def normalise(raw: str, subdomains: bool | None = None) -> str:
    """Turn user input into an entry, or raise DomainError.

    subdomains=True forces a leading dot, False removes it, None keeps what was
    typed (``.example.com`` and ``*.example.com`` both mean "with subdomains").
    """
    value = (raw or "").strip().lower()
    wildcard = False
    if value.startswith("*."):
        wildcard, value = True, value[2:]
    host = clean_host(value)
    if host.startswith("."):
        wildcard, host = True, host.lstrip(".")
    if not host:
        raise DomainError("Enter a domain name.")
    if not is_hostname(host):
        raise DomainError(f"'{raw.strip()[:80]}' isn't a valid domain name. Use something like example.com.")
    if subdomains is not None:
        wildcard = subdomains
    return ("." if wildcard else "") + host


def covers(entry: str, host: str) -> bool:
    """Does this entry match the host, the way Squid's dstdomain would?"""
    if entry.startswith("."):
        return host == entry[1:] or host.endswith(entry)
    return host == entry


class Matcher:
    """Fast "is this host covered by any entry" lookups."""

    def __init__(self, entries: Iterable[str]):
        entries = list(entries)  # may be a generator; it is read twice below
        self.exact = {e for e in entries if not e.startswith(".")}
        self.wild = {e[1:] for e in entries if e.startswith(".")}

    def match(self, host: str) -> str | None:
        """Return the entry that covers host, preferring the widest wildcard, or None."""
        parts = host.split(".")
        for i in range(len(parts) - 1, -1, -1):
            suffix = ".".join(parts[i:])
            if suffix in self.wild:
                return "." + suffix
        return host if host in self.exact else None

    def covering(self, entry: str) -> str | None:
        """Return a different, wider entry that already covers this entry, or None."""
        host = entry.lstrip(".")
        parts = host.split(".")
        for i in range(len(parts) - 1, 0, -1):
            suffix = ".".join(parts[i:])
            if suffix in self.wild:
                return "." + suffix
        if not entry.startswith(".") and host in self.wild:
            return "." + host
        return None


def effective(entries: Iterable[str]) -> tuple[list[str], dict[str, str]]:
    """Split entries into those Squid needs and those a wider entry already covers.

    Squid complains about overlapping dstdomain entries, so only the widest of
    any overlapping set is written to the ACL file.
    """
    unique = sorted(set(entries), key=sort_key)
    matcher = Matcher(unique)
    keep, redundant = [], {}
    for entry in unique:
        wider = matcher.covering(entry)
        if wider:
            redundant[entry] = wider
        else:
            keep.append(entry)
    return keep, redundant


def sort_key(entry: str) -> tuple[str, int]:
    """Alphabetical by name, ignoring the leading dot."""
    return (entry.lstrip("."), 0 if entry.startswith(".") else 1)


def render_acl(entries: Iterable[str], generated_by: str = "", generated_at: str = "") -> str:
    keep, _ = effective(entries)
    lines = [HEADER]
    if generated_by:
        lines.append(f"# Applied by {generated_by} at {generated_at}")
    return "\n".join(lines + keep) + "\n"


def acl_body(text: str) -> list[str]:
    """The entries in an ACL file, ignoring comments and blank lines."""
    return [line.strip() for line in (text or "").splitlines() if line.strip() and not line.lstrip().startswith("#")]


def same_entries(a: str, b: str) -> bool:
    """Do two ACL files allow the same things? Order and comments don't matter to Squid."""
    return set(acl_body(a)) == set(acl_body(b))


def _ordered(text: str) -> list[str]:
    return [line + "\n" for line in sorted(set(acl_body(text)), key=sort_key)]


def diff(old: str, new: str, old_label: str = "live", new_label: str = "pending") -> str:
    """A unified diff of two ACL files' entries, both in the same order so only real changes show."""
    return "".join(difflib.unified_diff(_ordered(old), _ordered(new), fromfile=old_label, tofile=new_label))


def parent_domain(host: str) -> str:
    """The registrable domain for a host (news.bbc.co.uk -> bbc.co.uk)."""
    from publicsuffix2 import get_sld

    return get_sld(host) or host
