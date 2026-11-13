"""Command line entry point.

Usage:
    python -m imgscan.cli --layout <layout-dir> --out <report.json>
"""

import argparse
import json
import os
import sys

from . import report as report_mod
from . import rules as rules_mod


def build_parser():
    parser = argparse.ArgumentParser(
        prog="imgscan",
        description="Scan an OCI image layout for sensitive files, "
                    "whiteout-deleted secrets and permission issues.",
    )
    parser.add_argument("--layout", required=True,
                        help="path to the OCI image layout directory")
    parser.add_argument("--out", required=True,
                        help="path to write the JSON report to")
    parser.add_argument("--rules", default=None,
                        help="optional JSON file overriding detection rules")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    rules = rules_mod.load_rules(args.rules)
    report = report_mod.build_report(args.layout, rules)

    out_dir = os.path.dirname(os.path.abspath(args.out))
    os.makedirs(out_dir, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=False)
        handle.write("\n")

    summary = report["summary"]
    print("summary: layers=%(layers)d final_files=%(final_files)d "
          "findings=%(findings)d" % summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
