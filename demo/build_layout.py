"""Build the demo OCI image layout at demo/layout.

The layout has two layers:
  layer 0 (gzip tar): .env (0644), id_rsa (0644), app.py (0644)
  layer 1 (plain tar): .wh..env  (whiteout deleting .env)

The image config leaves User empty, i.e. the container runs as root.
Everything is generated deterministically (fixed mtimes, gzip mtime=0).
"""

import gzip
import hashlib
import io
import json
import os
import shutil
import tarfile

ENV_CONTENT = b"DB_PASSWORD=s3cret-demo\nAPI_TOKEN=tok_demo_123\n"
ID_RSA_CONTENT = (
    b"-----BEGIN OPENSSH PRIVATE KEY-----\n"
    b"ZGVtby1mYWtlLWtleS1ub3QtcmVhbA==\n"
    b"-----END OPENSSH PRIVATE KEY-----\n"
)
APP_PY_CONTENT = b"print('hello from demo image')\n"


def make_tar(entries):
    """Build a tar archive in memory from (name, mode, content) tuples."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, mode, content in entries:
            info = tarfile.TarInfo(name)
            info.size = len(content)
            info.mode = mode
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            info.uname = "root"
            info.gname = "root"
            archive.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


def sha256_digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def write_blob(blobs_dir, data):
    digest = sha256_digest(data)
    algorithm, _, hexdigest = digest.partition(":")
    target_dir = os.path.join(blobs_dir, algorithm)
    os.makedirs(target_dir, exist_ok=True)
    path = os.path.join(target_dir, hexdigest)
    with open(path, "wb") as handle:
        handle.write(data)
    return digest, len(data)


def descriptor(media_type, digest, size):
    return {"mediaType": media_type, "digest": digest, "size": size}


def build_layout(dest):
    """Create the OCI layout directory at dest; return the layout path."""
    if os.path.isdir(dest):
        shutil.rmtree(dest)
    blobs_dir = os.path.join(dest, "blobs")
    os.makedirs(blobs_dir)

    layer0_plain = make_tar([
        (".env", 0o644, ENV_CONTENT),
        ("id_rsa", 0o644, ID_RSA_CONTENT),
        ("app.py", 0o644, APP_PY_CONTENT),
    ])
    layer0_blob = gzip.compress(layer0_plain, mtime=0)
    layer1_blob = make_tar([
        (".wh..env", 0o000, b""),
    ])

    layer0_digest, layer0_size = write_blob(blobs_dir, layer0_blob)
    layer1_digest, layer1_size = write_blob(blobs_dir, layer1_blob)

    config = {
        "architecture": "amd64",
        "os": "linux",
        "config": {
            "User": "",
            "Env": ["PATH=/usr/local/bin:/usr/bin:/bin"],
            "Cmd": ["python", "app.py"],
        },
        "rootfs": {
            "type": "layers",
            "diff_ids": [sha256_digest(layer0_plain), sha256_digest(layer1_blob)],
        },
        "history": [
            {"created_by": "demo layer 0: add app files"},
            {"created_by": "demo layer 1: remove .env"},
        ],
    }
    config_bytes = json.dumps(config, indent=2).encode("utf-8")
    config_digest, config_size = write_blob(blobs_dir, config_bytes)

    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": descriptor(
            "application/vnd.oci.image.config.v1+json",
            config_digest, config_size),
        "layers": [
            descriptor("application/vnd.oci.image.layer.v1.tar+gzip",
                       layer0_digest, layer0_size),
            descriptor("application/vnd.oci.image.layer.v1.tar",
                       layer1_digest, layer1_size),
        ],
    }
    manifest_bytes = json.dumps(manifest, indent=2).encode("utf-8")
    manifest_digest, manifest_size = write_blob(blobs_dir, manifest_bytes)

    index = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [descriptor(
            "application/vnd.oci.image.manifest.v1+json",
            manifest_digest, manifest_size)],
    }
    with open(os.path.join(dest, "index.json"), "w", encoding="utf-8") as handle:
        json.dump(index, handle, indent=2)
        handle.write("\n")
    with open(os.path.join(dest, "oci-layout"), "w", encoding="utf-8") as handle:
        json.dump({"imageLayoutVersion": "1.0.0"}, handle)
        handle.write("\n")
    return dest


def main():
    dest = os.path.join(os.path.dirname(os.path.abspath(__file__)), "layout")
    build_layout(dest)
    print("demo layout written to %s" % dest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
