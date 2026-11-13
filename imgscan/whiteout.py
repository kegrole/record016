"""Overlayfs whiteout semantics used by OCI/Docker image layers.

A layer deletes a lower-layer file 'dir/name' by containing an entry
'dir/.wh.name'.  A directory is made opaque (hiding all lower-layer
content beneath it) with an entry 'dir/.wh..wh..opq'.
"""

WHITEOUT_PREFIX = ".wh."
OPAQUE_MARKER = ".wh..wh..opq"


def normalize_path(path):
    """Normalize a tar member name to a clean relative POSIX path."""
    parts = []
    for segment in path.replace("\\", "/").split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            if parts:
                parts.pop()
            continue
        parts.append(segment)
    return "/".join(parts)


def _split(path):
    directory, _, base = path.rpartition("/")
    return directory, base


def is_whiteout(path):
    """True if the normalized path is a whiteout marker entry."""
    _, base = _split(path)
    return base.startswith(WHITEOUT_PREFIX)


def is_opaque(path):
    """True if the path is the opaque-directory marker."""
    _, base = _split(path)
    return base == OPAQUE_MARKER


def target_path(path):
    """Return the path a whiteout deletes, or None for opaque markers."""
    directory, base = _split(path)
    if base == OPAQUE_MARKER:
        return None
    target = base[len(WHITEOUT_PREFIX):]
    return "%s/%s" % (directory, target) if directory else target


def opaque_directory(path):
    """Return the directory an opaque marker applies to ('' for root)."""
    directory, _ = _split(path)
    return directory
