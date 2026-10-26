# Copyright (c) 2015, Frappe Technologies and Contributors
# License: MIT. See LICENSE
import smtplib
import textwrap
import unittest.mock
from unittest.mock import MagicMock

import frappe
from frappe.email.doctype.email_queue.email_queue import SendMailContext, get_email_retry_limit
from frappe.tests import IntegrationTestCase


class TestEmailQueue(IntegrationTestCase):
	def test_email_queue_deletion_based_on_modified_date(self):
		from frappe.email.doctype.email_queue.email_queue import EmailQueue

		old_record = frappe.get_doc(
			{
				"doctype": "Email Queue",
				"sender": "Test <test@example.com>",
				"show_as_cc": "",
				"message": "Test message",
				"status": "Sent",
				"priority": 1,
				"recipients": [
					{
						"recipient": "test_auth@test.com",
					}
				],
			}
		).insert()

		old_record.creation = "2010-01-01 00:00:01"
		old_record.recipients[0].creation = old_record.creation
		old_record.db_update_all()

		new_record = frappe.copy_doc(old_record)
		new_record.insert()

		EmailQueue.clear_old_logs()

		self.assertFalse(frappe.db.exists("Email Queue", old_record.name))
		self.assertFalse(frappe.db.exists("Email Queue Recipient", {"parent": old_record.name}))

		self.assertTrue(frappe.db.exists("Email Queue", new_record.name))
		self.assertTrue(frappe.db.exists("Email Queue Recipient", {"parent": new_record.name}))

	def test_failed_email_notification(self):
		subject = frappe.generate_hash()
		email_record = frappe.new_doc("Email Queue")
		email_record.sender = "Test <test@example.com>"
		email_record.message = textwrap.dedent(
			f"""\
		MIME-Version: 1.0
		Message-Id: {frappe.generate_hash()}
		X-Original-From: Test <test@example.com>
		Subject: {subject}
		From: Test <test@example.com>
		To: <!--recipient-->
		Date: {frappe.utils.now_datetime().strftime("%a, %d %b %Y %H:%M:%S %z")}
		Reply-To: test@example.com
		X-Frappe-Site: {frappe.local.site}
		"""
		)
		email_record.status = "Error"
		email_record.retry = get_email_retry_limit()
		email_record.priority = 1
		email_record.reference_doctype = "User"
		email_record.reference_name = "Administrator"
		email_record.insert()

		# Simulate an exception so that we get a notification
		try:
			with SendMailContext(queue_doc=email_record):
				raise Exception("Test Exception")
		except Exception:
			pass

		notification_log = frappe.db.get_value(
			"Notification Log",
			{"subject": f"Failed to send email with subject: {subject}"},
		)
		self.assertTrue(notification_log)

	def test_perf_reusing_smtp_server(self):
		"""Ensure that same smtpserver instance is being returned when retrieved multiple times."""

		self.assertTrue(frappe.new_doc("Email Queue").get_email_account()._from_site_config)

		def get_server(q):
			return q.get_email_account().get_smtp_server()

		self.assertIs(get_server(frappe.new_doc("Email Queue")), get_server(frappe.new_doc("Email Queue")))

		q1 = frappe.new_doc("Email Queue", email_account="_Test Email Account 1")
		q2 = frappe.new_doc("Email Queue", email_account="_Test Email Account 1")
		self.assertIsNot(get_server(frappe.new_doc("Email Queue")), get_server(q1))
		self.assertIs(get_server(q1), get_server(q2))

	def test_redacts_message_only_once_sent(self):
		"""A failed send must keep the message intact, it is the only copy the retry has."""
		link = f"http://example.com/update-password?key={frappe.generate_hash()}"
		email_record = frappe.new_doc(
			"Email Queue",
			sender="Test <test@example.com>",
			show_as_cc="",
			email_account="_Test Email Account 1",
			message=textwrap.dedent(
				f"""\
			MIME-Version: 1.0
			Content-Type: text/plain; charset="utf-8"
			Message-Id: {frappe.generate_hash()}
			Subject: Welcome
			From: Test <test@example.com>
			To: <!--recipient-->

			Hello, complete your registration at {link}
			"""
			),
			status="Not Sent",
			priority=1,
			redact_message_after_send=1,
			recipients=[{"recipient": "test_redact@example.com"}],
		).insert()

		mock_session = MagicMock()
		mock_session.has_extn.return_value = False
		mock_session.sendmail.side_effect = smtplib.SMTPRecipientsRefused(
			{"test_redact@example.com": (450, b"Mailbox busy")}
		)
		mock_smtp_server = MagicMock()
		mock_smtp_server.session = mock_session

		frappe.flags.testing_email = True
		try:
			with self.assertRaises(smtplib.SMTPRecipientsRefused):
				email_record.send(smtp_server_instance=mock_smtp_server)

			self.assertIn(link, frappe.db.get_value("Email Queue", email_record.name, "message"))

			mock_session.sendmail.side_effect = None
			email_record.reload()
			email_record.send(smtp_server_instance=mock_smtp_server)
		finally:
			frappe.flags.testing_email = False

		self.assertIn(link, mock_session.sendmail.call_args.kwargs["msg"].decode())
		self.assertNotIn(link, frappe.db.get_value("Email Queue", email_record.name, "message"))


class TestExternallyDeliveredEmailQueue(IntegrationTestCase):
	"""Rows owned by another backend (`crm_delivery_owner = "brick"`) are never sent here."""

	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		from frappe.custom.doctype.custom_field.custom_field import create_custom_field

		cls.created_field = not frappe.db.has_column("Email Queue", "crm_delivery_owner")
		if cls.created_field:
			create_custom_field("Email Queue", {"fieldname": "crm_delivery_owner", "fieldtype": "Data"})

	@classmethod
	def tearDownClass(cls):
		if cls.created_field:
			frappe.delete_doc("Custom Field", "Email Queue-crm_delivery_owner", force=True)
			frappe.db.commit()
		super().tearDownClass()

	def make_queue(self, owner, status="Not Sent"):
		row = frappe.get_doc(
			{
				"doctype": "Email Queue",
				"sender": "Test <test@example.com>",
				"message": "Test message",
				"status": status,
				"crm_delivery_owner": owner,
				"recipients": [{"recipient": "test_external@example.com"}],
			}
		).insert()
		frappe.db.set_value(
			"Email Queue",
			row.name,
			{"creation": "2010-01-01 00:00:01", "modified": "2010-01-01 00:00:01"},
			update_modified=False,
		)
		return frappe.get_doc("Email Queue", row.name)

	def test_send_skips_brick_rows_even_when_forced(self):
		row = self.make_queue("brick")
		with unittest.mock.patch.object(SendMailContext, "__enter__") as enter:
			row.send()
			row.send(force_send=True)
		enter.assert_not_called()

	def test_frappe_rows_still_send(self):
		row = self.make_queue("frappe")
		with unittest.mock.patch.object(SendMailContext, "__enter__", side_effect=RuntimeError) as enter:
			with self.assertRaises(RuntimeError):
				row.send(force_send=True)
		enter.assert_called_once()

	def test_get_queue_leaves_out_brick_rows(self):
		from frappe.email.queue import get_queue

		brick = self.make_queue("brick")
		frappe_row = self.make_queue("frappe")
		unset = self.make_queue(None)
		names = {row.name for row in get_queue()}
		self.assertNotIn(brick.name, names)
		self.assertIn(frappe_row.name, names)
		self.assertIn(unset.name, names)

	def test_retry_leaves_stuck_brick_rows_to_their_owner(self):
		from frappe.email.queue import retry_sending_emails

		brick = self.make_queue("brick", status="Sending")
		frappe_row = self.make_queue("frappe", status="Sending")
		retry_sending_emails()
		self.assertEqual(frappe.db.get_value("Email Queue", brick.name, "status"), "Sending")
		self.assertNotEqual(frappe.db.get_value("Email Queue", frappe_row.name, "status"), "Sending")
