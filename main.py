import argparse
import json

from auditor.checks import (
    check_container_running_as_root,
    check_privileged_container,
    check_dangerous_mounts,
)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Container Security Auditor"
    )

    parser.add_argument(
        "--input",
        required=True,
        help="Path to container inspect JSON file",
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

    for f in findings:
        print(f"{f.severity.value} - {f.observation}")


if __name__ == "__main__":
    main()
