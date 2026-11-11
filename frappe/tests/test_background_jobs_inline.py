from unittest.mock import MagicMock, patch

import frappe
from frappe.tests import IntegrationTestCase

INLINE = {"run_background_jobs_inline": 1}


def _make_todo(description: str) -> str:
	return frappe.get_doc({"doctype": "ToDo", "description": description}).insert().name


def _make_todo_then_fail(description: str) -> None:
	_make_todo(description)
	raise ValueError("job failed")


class TestRunBackgroundJobsInline(IntegrationTestCase):
	def test_runs_at_once_without_touching_the_queue(self):
		with (
			patch.dict(frappe.conf, INLINE),
			patch("frappe.utils.background_jobs.get_queue", side_effect=AssertionError("queued")),
		):
			name = frappe.enqueue(_make_todo, description="inline now")
		self.assertTrue(frappe.db.exists("ToDo", name))

	def test_a_failing_job_is_logged_and_undone_without_failing_the_caller(self):
		before = _make_todo("caller write")
		errors = frappe.db.count("Error Log")
		with patch.dict(frappe.conf, INLINE):
			result = frappe.enqueue(
				"frappe.tests.test_background_jobs_inline._make_todo_then_fail",
				description="inline failed",
			)
		self.assertIsNone(result)
		self.assertTrue(frappe.db.exists("ToDo", before))
		self.assertFalse(frappe.db.exists("ToDo", {"description": "inline failed"}))
		self.assertEqual(frappe.db.count("Error Log"), errors + 1)

	def test_after_commit_jobs_wait_for_the_commit_and_commit_their_writes(self):
		with patch.dict(frappe.conf, INLINE):
			self.assertIsNone(
				frappe.enqueue(_make_todo, description="inline later", enqueue_after_commit=True)
			)
		self.assertFalse(frappe.db.exists("ToDo", {"description": "inline later"}))
		with patch.object(frappe.db, "commit") as commit:
			frappe.db.after_commit.run()
		self.assertTrue(frappe.db.exists("ToDo", {"description": "inline later"}))
		commit.assert_called_once()

	def test_without_the_flag_jobs_go_to_the_queue(self):
		queue = MagicMock(count=0)
		with patch("frappe.utils.background_jobs.get_queue", return_value=queue):
			frappe.enqueue(_make_todo, description="queued")
		queue.enqueue_call.assert_called_once()
		self.assertFalse(frappe.db.exists("ToDo", {"description": "queued"}))

	def test_deferred_inserts_land_after_a_rollback_without_redis(self):
		with (
			patch.dict(frappe.conf, INLINE),
			patch.object(frappe.cache, "rpush", side_effect=AssertionError("pushed to redis")),
		):
			frappe.get_doc(doctype="Error Log", method="inline deferred", error="boom").deferred_insert()
			self.assertFalse(frappe.db.exists("Error Log", {"method": "inline deferred"}))
			frappe.db.rollback()
		self.assertTrue(frappe.db.exists("Error Log", {"method": "inline deferred"}))
