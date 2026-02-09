from auditor.checks.mounts import check_dangerous_mounts
from auditor.models import Severity


def test_docker_socket_mount_detected():
    container_info = {
        "Mounts": [
            {
                "Source": "/var/run/docker.sock",
                "Destination": "/var/run/docker.sock",
            }
        ]
    }

    findings = check_dangerous_mounts(container_info)

    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


def test_root_filesystem_mount_detected():
    container_info = {
        "Mounts": [
            {
                "Source": "/",
                "Destination": "/host",
            }
        ]
    }

    findings = check_dangerous_mounts(container_info)

    assert len(findings) == 1
    assert "root filesystem" in findings[0].explanation.lower()


def test_safe_mounts_ok():
    container_info = {
        "Mounts": [
            {
                "Source": "/data",
                "Destination": "/app/data",
            }
        ]
    }

    findings = check_dangerous_mounts(container_info)

    assert findings == []
