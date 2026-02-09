from auditor.checks.privileged import check_privileged_container
from auditor.models import Severity


def test_privileged_container_detected():
    container_info = {
        "HostConfig": {
            "Privileged": True
        }
    }

    findings = check_privileged_container(container_info)

    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


def test_non_privileged_container_ok():
    container_info = {
        "HostConfig": {
            "Privileged": False
        }
    }

    findings = check_privileged_container(container_info)

    assert findings == []
