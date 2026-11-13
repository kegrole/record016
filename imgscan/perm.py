"""Permission bits and runtime-identity checks."""

# Bit that makes a file readable by 'other' (world-readable).
WORLD_READABLE_BIT = 0o004


def is_world_readable(mode):
    """True if the tar entry mode grants read to others."""
    return bool(mode & WORLD_READABLE_BIT)


def mode_string(mode):
    """Render permission bits as a zero-padded octal string, e.g. 0644."""
    return format(mode & 0o7777, "04o")


def runtime_user(config):
    """Return the User the image runs as ('' means unset)."""
    image_config = config.get("config") or {}
    user = image_config.get("User")
    if user is None:
        return ""
    return str(user)


def is_root_user(config):
    """True if the image config runs as root (empty, 0 or 'root')."""
    user = runtime_user(config).strip()
    if user == "":
        return True
    name, _, group = user.partition(":")
    return name in ("0", "root") or (name == "" and group in ("0", "root"))
