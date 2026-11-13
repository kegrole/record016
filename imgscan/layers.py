"""Apply image layers in manifest order and compute the final filesystem.

Every regular file ever seen is recorded as a FileEntry (history), and
every whiteout deletion of an existing lower-layer file is recorded as a
DeleteEvent, so historical analysis can trace files that no longer exist
in the final image.
"""

from dataclasses import dataclass, field

from . import blobs, whiteout

_MAX_CONTENT_BYTES = 8 * 1024 * 1024


@dataclass
class FileEntry:
    path: str
    layer_index: int
    layer_digest: str
    mode: int
    size: int
    content: bytes = b""


@dataclass
class DeleteEvent:
    path: str
    layer_index: int
    layer_digest: str
    whiteout_path: str


@dataclass
class LayerResult:
    entries: list = field(default_factory=list)   # every file ever added
    deletes: list = field(default_factory=list)   # whiteout deletions
    final: dict = field(default_factory=dict)     # path -> FileEntry


def apply_layers(layout_dir, layer_descriptors):
    """Replay layers in order; return history, deletions and final state."""
    result = LayerResult()
    for index, descriptor in enumerate(layer_descriptors):
        digest = descriptor["digest"]
        archive = blobs.open_blob_tar(layout_dir, digest)
        with archive:
            for member in archive:
                if not member.isfile():
                    continue
                path = whiteout.normalize_path(member.name)
                if not path:
                    continue
                if whiteout.is_whiteout(path):
                    _apply_whiteout(result, path, index, digest)
                    continue
                extracted = archive.extractfile(member)
                content = b""
                if extracted is not None and member.size <= _MAX_CONTENT_BYTES:
                    content = extracted.read()
                entry = FileEntry(
                    path=path,
                    layer_index=index,
                    layer_digest=digest,
                    mode=member.mode,
                    size=member.size,
                    content=content,
                )
                result.entries.append(entry)
                result.final[path] = entry
    return result


def _apply_whiteout(result, path, layer_index, digest):
    if whiteout.is_opaque(path):
        directory = whiteout.opaque_directory(path)
        prefix = directory + "/" if directory else ""
        for existing in sorted(list(result.final)):
            if existing.startswith(prefix):
                result.deletes.append(DeleteEvent(
                    path=existing,
                    layer_index=layer_index,
                    layer_digest=digest,
                    whiteout_path=path,
                ))
                del result.final[existing]
        return
    target = whiteout.target_path(path)
    if target in result.final:
        result.deletes.append(DeleteEvent(
            path=target,
            layer_index=layer_index,
            layer_digest=digest,
            whiteout_path=path,
        ))
        del result.final[target]
