from auditor.models import Severity


def exit_code_from_findings(findings):
    if any(f.severity == Severity.HIGH for f in findings):
        return 2
    if any(f.severity == Severity.MEDIUM for f in findings):
        return 1
    return 0
