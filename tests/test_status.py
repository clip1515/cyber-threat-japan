import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from analyzers.status import compute_status


class TestStatus(unittest.TestCase):
    def test_new_record_is_new(self):
        status, _ = compute_status(
            is_new_record=True, existing_status=None, existing_severity=None,
            new_severity="Medium", has_mitigation_info=False,
            first_seen_at=None, last_updated_at=None,
        )
        self.assertEqual(status, "NEW")

    def test_severity_increase_is_escalated(self):
        status, _ = compute_status(
            is_new_record=False, existing_status="ACTIVE", existing_severity="Medium",
            new_severity="Critical", has_mitigation_info=False,
            first_seen_at=None, last_updated_at=None,
        )
        self.assertEqual(status, "ESCALATED")

    def test_mitigation_info_marks_mitigated(self):
        status, _ = compute_status(
            is_new_record=False, existing_status="ACTIVE", existing_severity="High",
            new_severity="High", has_mitigation_info=True,
            first_seen_at=None, last_updated_at=None,
        )
        self.assertEqual(status, "MITIGATED")

    def test_closed_incident_reactivates_on_update(self):
        status, _ = compute_status(
            is_new_record=False, existing_status="CLOSED", existing_severity="Medium",
            new_severity="Medium", has_mitigation_info=False,
            first_seen_at=None, last_updated_at=None,
        )
        self.assertEqual(status, "ACTIVE")

    def test_no_change_stays_active(self):
        old_date = datetime(2020, 1, 1, tzinfo=timezone.utc).isoformat()
        status, _ = compute_status(
            is_new_record=False, existing_status="ACTIVE", existing_severity="High",
            new_severity="High", has_mitigation_info=False,
            first_seen_at=old_date, last_updated_at=old_date,
        )
        self.assertEqual(status, "ACTIVE")


if __name__ == "__main__":
    unittest.main()