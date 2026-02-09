from auditor.models import Finding, Severity


def check_container_running_as_root(container_info):
    findings = []

    user = (
        container_info
        .get("Config", {})
        .get("User", "")
        .strip()
    )

    if user == "" or user == "0":
        findings.append(
            Finding(
                scope="Container configuration",
                observation="Container is running as root user",
                severity=Severity.HIGH,
                explanation=(
                    "Containers running as root increase the risk of container "
                    "breakout and privilege escalation."
                ),
                recommendation=(
                    "Configure the container to run as a non-root user using "
                    "the USER directive in the Dockerfile or runtime options."
                ),
            )
        )

    return findings
