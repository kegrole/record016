"""Configurable sensitive-file detection rules.

Default rules can be overridden/extended with a JSON file passed via
--rules.  The JSON object may contain any of the keys of DEFAULT_RULES;
lists given there replace the defaults.
"""

import fnmatch
import json
import os

DEFAULT_RULES = {
    # fnmatch patterns matched against the file's base name.
    "filename_patterns": [
        ".env", ".env.*",
        "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
        "*.pem", "*.key", "*.p12", "*.pfx", "*.jks", "*.keystore",
        "*.kdbx", "*.credentials",
        ".netrc", ".npmrc", ".pgpass", ".htpasswd",
        "credentials", "shadow", "htpasswd",
    ],
    # Lower-cased substrings searched in scanned file content.
    "content_keywords": [
        "password", "passwd", "token", "secret",
        "api_key", "apikey", "private key",
    ],
    # Extensions (and dotfile base names) eligible for content scanning.
    "content_scan_names": [
        ".env", ".conf", ".cfg", ".config", ".ini", ".json",
        ".yaml", ".yml", ".toml", ".properties", ".sh", ".py",
        ".txt", ".pem", ".key", ".env.*",
    ],
    # Files larger than this are not content-scanned.
    "content_scan_max_bytes": 1048576,
}


def load_rules(path=None):
    """Return the default rules, optionally overridden by a JSON file."""
    rules = {key: (list(value) if isinstance(value, list) else value)
             for key, value in DEFAULT_RULES.items()}
    if path:
        with open(path, "r", encoding="utf-8") as handle:
            overrides = json.load(handle)
        if not isinstance(overrides, dict):
            raise ValueError("rules file must contain a JSON object")
        rules.update(overrides)
    return rules


def match_filename(path, rules):
    """Return the matching filename pattern for a path, or None."""
    base = path.rsplit("/", 1)[-1]
    for pattern in rules.get("filename_patterns", []):
        if fnmatch.fnmatch(base, pattern):
            return pattern
    return None


def _scan_name(path):
    """Suffix used to decide content scanning; dotfiles use their name."""
    base = path.rsplit("/", 1)[-1]
    if base.startswith(".") and base.count(".") == 1:
        return base
    _, dot, ext = base.rpartition(".")
    return dot + ext if dot else ""


def should_scan_content(path, size, rules):
    """True if the file's content should be keyword-scanned."""
    if size > rules.get("content_scan_max_bytes", 0):
        return False
    name = _scan_name(path)
    for pattern in rules.get("content_scan_names", []):
        if fnmatch.fnmatch(name, pattern):
            return True
    return False


def match_content(content, rules):
    """Return the first sensitive keyword found in content, or None."""
    try:
        text = content.decode("utf-8", errors="ignore").lower()
    except AttributeError:
        return None
    for keyword in rules.get("content_keywords", []):
        if keyword.lower() in text:
            return keyword
    return None
