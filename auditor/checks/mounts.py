from auditor.models import Finding, Severity


DANGEROUS_MOUNTS = {
    "/",
    "/proc",
    "/sys",
    "/var/run/docker.sock",
}


def check_dangerous_mounts(container_info):
    findings = []

    mounts = container_info.get("Mounts", [])

    for mount in mounts:
        source = mount.get("Source", "")

        if source in DANGEROUS_MOUNTS:
            explanation = (
                "Mounting sensitive host paths into a container can allow "
                "container escape or direct host manipulation."
            )

            if source == "/":
                explanation = (
                    "Mounting the host root filesystem into a container "
                    "gives the container full access to the host system."
                )

            findings.append(
                Finding(
                    scope="Container filesystem",
                    observation=f"Dangerous host mount detected: {source}",
                    severity=Severity.HIGH,
                    explanation=explanation,
                    recommendation=(
                        "Remove the dangerous mount and redesign the container "
                        "to operate without direct access to host internals."
                    ),
                )
            )

    return findings
