import argparse
import json
import sys

from auditor.checks import (
    check_container_running_as_root,
    check_privileged_container,
    check_dangerous_mounts,
)
from auditor.utils import exit_code_from_findings


def parse_args():
    parser = argparse.ArgumentParser(
        description="Container Security Auditor"
    )

    parser.add_argument(
        "--input",
        required=True,
        help="Path to container inspect JSON file",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON",
    )

    return parser.parse_args()


def main():
    args = parse_args()

    with open(args.input, "r") as f:
        container_info = json.load(f)

    findings = []
    findings.extend(check_container_running_as_root(container_info))
    findings.extend(check_privileged_container(container_info))
    findings.extend(check_dangerous_mounts(container_info))

    if args.json:
        output = {
            "findings": [
                {
                    "scope": f.scope,
                    "observation": f.observation,
                    "severity": f.severity.value,
                    "explanation": f.explanation,
                    "recommendation": f.recommendation,
                }
                for f in findings
            ]
        }
        print(json.dumps(output))
    else:
        for f in findings:
            print(f"{f.severity.value} - {f.observation}")

    sys.exit(exit_code_from_findings(findings))


if __name__ == "__main__":
    main()
