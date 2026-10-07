"""Permission summaries must respect action-specific controller denials."""

from unittest.mock import patch

import frappe
from frappe.permissions import get_doc_permissions
from frappe.tests import UnitTestCase


class TestDocumentPermissionSummary(UnitTestCase):
	def setUp(self) -> None:
		self.doc = frappe._dict(doctype="Summary Test", owner="user@example.com")
		self.enterContext(
			patch(
				"frappe.permissions.frappe.get_meta",
				return_value=frappe._dict(is_submittable=0, allow_import=0),
			)
		)
		self.role_permissions = self.enterContext(
			patch(
				"frappe.permissions.get_role_permissions", return_value={"read": 1, "write": 1, "delete": 1}
			)
		)
		self.enterContext(patch("frappe.permissions.has_user_permission", return_value=True))

	def test_summary_evaluates_each_action(self) -> None:
		# An action-specific hook rejects None as well as write. A summary
		# must retain permitted read/delete while masking the denied write.
		def controller_permission(doc, ptype: str | None, **kwargs) -> bool:
			return ptype in {"read", "delete"}

		with patch("frappe.permissions.has_controller_permissions", side_effect=controller_permission):
			permissions = get_doc_permissions(self.doc, user="user@example.com")
		self.assertEqual(permissions["read"], 1)
		self.assertEqual(permissions["delete"], 1)
		self.assertEqual(permissions["write"], 0)

	def test_controller_cannot_add_a_role_permission(self) -> None:
		self.role_permissions.return_value = {"read": 1, "delete": 0}
		with patch("frappe.permissions.has_controller_permissions", return_value=True):
			permissions = get_doc_permissions(self.doc, user="user@example.com")
		self.assertEqual(permissions["delete"], 0)

	def test_explicit_delete_check_remains_denied(self) -> None:
		with patch("frappe.permissions.has_controller_permissions", return_value=False):
			permissions = get_doc_permissions(self.doc, user="user@example.com", ptype="delete")
		self.assertEqual(permissions, {"delete": 0})
