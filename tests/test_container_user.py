from auditor.checks.container_user import check_container_running_as_root
from auditor.models import Severity


def test_container_running_as_root_detected():
    container_info = {
        "Id": "abc123",
        "Config": {
            "User": ""
        }
    }

    findings = check_container_running_as_root(container_info)

    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


def test_container_running_as_non_root_ok():
    container_info = {
        "Id": "def456",
        "Config": {
            "User": "1000"
        }
    }

    findings = check_container_running_as_root(container_info)

    assert findings == []
