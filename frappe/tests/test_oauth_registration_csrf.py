import unittest
from types import SimpleNamespace
from unittest.mock import patch

from werkzeug.test import EnvironBuilder
from werkzeug.wrappers import Request

import frappe
from frappe.auth import HTTPRequest


class TestOAuthRegistrationCSRF(unittest.TestCase):
	def test_only_guest_registration_bypasses_session_csrf(self) -> None:
		registration = "/api/method/frappe.integrations.oauth2.register_client"
		for user, path, allowed in (
			("Guest", registration, True),
			("test@example.com", registration, False),
			("Guest", "/api/method/frappe.integrations.oauth2.approve", False),
			("Guest", registration + "/other", False),
		):
			with self.subTest(user=user, path=path):
				request = Request(EnvironBuilder(path=path, method="POST").get_environ())
				boundary = SimpleNamespace(
					request=request,
					conf=SimpleNamespace(ignore_csrf=False),
					session=SimpleNamespace(user=user, data=SimpleNamespace(csrf_token="session-token")),
					form_dict={},
					flags=SimpleNamespace(),
					get_request_header=request.headers.get,
					throw=lambda *args: self._reject(),
					CSRFTokenError=frappe.CSRFTokenError,
				)
				with (
					patch("frappe.auth.frappe", boundary),
					patch("frappe.auth.should_skip_token_validation", return_value=False),
					patch.object(HTTPRequest, "is_allowed_referrer", return_value=False),
					patch("frappe.auth._", side_effect=lambda text: text),
				):
					handler = HTTPRequest.__new__(HTTPRequest)
					if allowed:
						handler.validate_csrf_token()
					else:
						with self.assertRaises(frappe.CSRFTokenError):
							handler.validate_csrf_token()

	def _reject(self) -> None:
		raise frappe.CSRFTokenError
