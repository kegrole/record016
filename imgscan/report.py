"""Assemble findings from a scanned layout into a JSON report."""

from . import layers as layers_mod
from . import layout as layout_mod
from . import perm
from . import rules as rules_mod

KIND_SENSITIVE_FILE = "sensitive_file"
KIND_WHITEOUT_DELETED = "whiteout_deleted"
KIND_ROOT_USER = "root_user"

_FINDING_FIELDS = ("kind", "path", "layer_index", "layer_digest", "mode", "detail")


def _finding(kind, path, layer_index, layer_digest, mode, detail):
    return {
        "kind": kind,
        "path": path,
        "layer_index": layer_index,
        "layer_digest": layer_digest,
        "mode": mode,
        "detail": detail,
    }


def _sensitive_findings(result, rules):
    findings = []
    for entry in result.entries:
        reasons = []
        pattern = rules_mod.match_filename(entry.path, rules)
        if pattern:
            reasons.append("filename matches sensitive rule '%s'" % pattern)
        if rules_mod.should_scan_content(entry.path, entry.size, rules):
            keyword = rules_mod.match_content(entry.content, rules)
            if keyword:
                reasons.append("content contains sensitive keyword '%s'" % keyword)
        if not reasons:
            continue
        detail = "; ".join(reasons)
        if perm.is_world_readable(entry.mode):
            detail += "; world-readable (mode %s)" % perm.mode_string(entry.mode)
        findings.append(_finding(
            KIND_SENSITIVE_FILE,
            entry.path,
            entry.layer_index,
            entry.layer_digest,
            perm.mode_string(entry.mode),
            detail,
        ))
    return findings


def _whiteout_findings(result):
    findings = []
    for delete in result.deletes:
        origin = None
        for entry in result.entries:
            if entry.path == delete.path and entry.layer_index < delete.layer_index:
                if origin is None or entry.layer_index < origin.layer_index:
                    origin = entry
        if origin is not None:
            detail = (
                "deleted by whiteout '%s' in layer %d; still recoverable "
                "from layer %d (blob %s)"
                % (delete.whiteout_path, delete.layer_index,
                   origin.layer_index, origin.layer_digest)
            )
        else:
            detail = (
                "deleted by whiteout '%s' in layer %d; not present in any "
                "lower layer" % (delete.whiteout_path, delete.layer_index)
            )
        findings.append(_finding(
            KIND_WHITEOUT_DELETED,
            delete.path,
            delete.layer_index,
            delete.layer_digest,
            None,
            detail,
        ))
    return findings


def _config_findings(config):
    findings = []
    if perm.is_root_user(config):
        user = perm.runtime_user(config)
        if user.strip() == "":
            detail = "image config User is empty; container runs as root"
        else:
            detail = "image config User is '%s'; container runs as root" % user
        findings.append(_finding(KIND_ROOT_USER, None, None, None, None, detail))
    return findings


def build_report(layout_dir, rules=None):
    """Scan an OCI layout directory and return the report as a dict."""
    if rules is None:
        rules = rules_mod.load_rules()
    image = layout_mod.load_layout(layout_dir)
    result = layers_mod.apply_layers(layout_dir, image.layer_descriptors)

    findings = []
    findings.extend(_sensitive_findings(result, rules))
    findings.extend(_whiteout_findings(result))
    findings.extend(_config_findings(image.config))

    final_files = sorted(result.final)
    return {
        "findings": findings,
        "final_files": final_files,
        "summary": {
            "layers": image.layer_count,
            "final_files": len(final_files),
            "findings": len(findings),
        },
    }
