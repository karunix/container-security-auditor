from auditor.models import Finding, Severity


def check_privileged_container(container_info):
    findings = []

    privileged = (
        container_info
        .get("HostConfig", {})
        .get("Privileged", False)
    )

    if privileged:
        findings.append(
            Finding(
                scope="Container configuration",
                observation="Container is running in privileged mode",
                severity=Severity.HIGH,
                explanation=(
                    "Privileged containers have almost unrestricted access "
                    "to the host system, significantly increasing the risk "
                    "of host compromise."
                ),
                recommendation=(
                    "Avoid running containers in privileged mode. Use "
                    "capability-based permissions instead where possible."
                ),
            )
        )

    return findings
