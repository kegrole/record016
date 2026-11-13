"""Content-addressable blob access for an OCI image layout.

Blobs live at <layout>/blobs/<algorithm>/<hex>. Layer blobs may be plain
tar or gzip-compressed tar; compression is detected by magic bytes.
"""

import gzip
import io
import json
import os
import tarfile

_GZIP_MAGIC = b"\x1f\x8b"


def blob_path(layout_dir, digest):
    """Map a digest string (sha256:abc...) to its blob file path."""
    algorithm, sep, hexdigest = digest.partition(":")
    if not sep or not algorithm or not hexdigest:
        raise ValueError("malformed digest: %r" % digest)
    return os.path.join(layout_dir, "blobs", algorithm, hexdigest)


def read_blob(layout_dir, digest):
    """Return the raw bytes of a blob."""
    path = blob_path(layout_dir, digest)
    with open(path, "rb") as handle:
        return handle.read()


def read_blob_json(layout_dir, digest):
    """Read a blob and parse it as JSON."""
    return json.loads(read_blob(layout_dir, digest).decode("utf-8"))


def open_blob_tar(layout_dir, digest):
    """Open a layer blob as a tarfile, transparently handling gzip."""
    data = read_blob(layout_dir, digest)
    if data[:2] == _GZIP_MAGIC:
        data = gzip.decompress(data)
    return tarfile.open(fileobj=io.BytesIO(data), mode="r:")
