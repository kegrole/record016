"""Parsing of the OCI image layout directory structure.

Expected structure:

    <layout>/
        oci-layout            (optional version marker)
        index.json            (points at the image manifest blob)
        blobs/sha256/<hex>    (manifest, config and layer blobs)
"""

import json
import os
from dataclasses import dataclass, field

from . import blobs


@dataclass
class ImageLayout:
    """Parsed view of an OCI image layout directory."""

    root: str
    index: dict
    manifest: dict
    manifest_digest: str
    config: dict
    layer_descriptors: list = field(default_factory=list)

    @property
    def layer_count(self):
        return len(self.layer_descriptors)


def load_layout(layout_dir):
    """Load index.json, the referenced manifest and the image config."""
    index_path = os.path.join(layout_dir, "index.json")
    if not os.path.isfile(index_path):
        raise FileNotFoundError("index.json not found in %s" % layout_dir)
    with open(index_path, "r", encoding="utf-8") as handle:
        index = json.load(handle)

    manifest_descriptors = index.get("manifests") or []
    if not manifest_descriptors:
        raise ValueError("index.json contains no manifest descriptors")
    manifest_descriptor = manifest_descriptors[0]
    manifest_digest = manifest_descriptor["digest"]
    manifest = blobs.read_blob_json(layout_dir, manifest_digest)

    config_descriptor = manifest.get("config")
    if not config_descriptor:
        raise ValueError("manifest has no config descriptor")
    config = blobs.read_blob_json(layout_dir, config_descriptor["digest"])

    return ImageLayout(
        root=layout_dir,
        index=index,
        manifest=manifest,
        manifest_digest=manifest_digest,
        config=config,
        layer_descriptors=list(manifest.get("layers") or []),
    )
