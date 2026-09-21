from unittest.mock import patch

from werkzeug.test import EnvironBuilder
from werkzeug.wrappers import Request

import frappe
from frappe.security.request_policy import DenialReason, evaluate_request
from frappe.tests import UnitTestCase


@frappe.whitelist(allow_guest=True, methods=["POST"])
def _policy_test_guest_endpoint():
	return "ok"


@frappe.whitelist(methods=["POST"])
def _policy_test_authed_endpoint():
	return "ok"


class TestOriginRequestPolicy(UnitTestCase):
	GUEST_PATH = "/api/method/frappe.tests.test_request_policy._policy_test_guest_endpoint"
	AUTHED_PATH = "/api/method/frappe.tests.test_request_policy._policy_test_authed_endpoint"

	def make_request(
		self,
		*,
		path="/api/method/example.mutate",
		headers=None,
		content_type="application/json",
	):
		return Request(
			EnvironBuilder(
				method="POST",
				path=path,
				headers=headers or {},
				content_type=content_type,
			).get_environ()
		)

	def evaluate(self, request, *, user="test@example.com", mechanism="session"):
		with (
			patch.object(frappe, "conf", frappe._dict({
				"trusted_browser_origins": ["https://crm.pixelwand.io"],
			})),
			patch.object(frappe.local, "site", "test_site", create=True),
			patch.object(frappe.local, "session", frappe._dict({"user": user}), create=True),
			patch.object(frappe.local, "auth_mechanism", mechanism, create=True),
			patch.object(
				frappe,
				"get_request_header",
				side_effect=lambda name: request.headers.get(name, ""),
			),
		):
			return evaluate_request(request)

	def test_accepts_exact_origin_and_same_origin_fetch(self):
		decision = self.evaluate(
			self.make_request(
				headers={
					"Origin": "https://crm.pixelwand.io",
					"Sec-Fetch-Site": "same-origin",
				}
			)
		)
		self.assertTrue(decision.allowed)

	def test_rejects_origin_suffix_bypass(self):
		decision = self.evaluate(
			self.make_request(
				headers={
					"Origin": "https://crm.pixelwand.io.attacker.example",
					"Sec-Fetch-Site": "same-origin",
				}
			)
		)
		self.assertEqual(decision.reason, DenialReason.UNTRUSTED_ORIGIN)

	def test_rejects_cross_site_and_same_site_fetches(self):
		for fetch_site in ("cross-site", "same-site"):
			with self.subTest(fetch_site=fetch_site):
				decision = self.evaluate(
					self.make_request(
						headers={
							"Origin": "https://crm.pixelwand.io",
							"Sec-Fetch-Site": fetch_site,
						}
					)
				)
				self.assertEqual(decision.reason, DenialReason.CROSS_SITE_FETCH)

	def test_rejects_missing_origin(self):
		decision = self.evaluate(
			self.make_request(headers={"Sec-Fetch-Site": "same-origin"})
		)
		self.assertEqual(decision.reason, DenialReason.MISSING_ORIGIN)

	def test_rejects_missing_fetch_metadata(self):
		decision = self.evaluate(
			self.make_request(headers={"Origin": "https://crm.pixelwand.io"})
		)
		self.assertEqual(decision.reason, DenialReason.MISSING_FETCH_METADATA)

	def test_rejects_origin_with_a_path(self):
		decision = self.evaluate(
			self.make_request(
				headers={
					"Origin": "https://crm.pixelwand.io/path",
					"Sec-Fetch-Site": "same-origin",
				}
			)
		)
		self.assertEqual(decision.reason, DenialReason.MALFORMED_ORIGIN)

	def test_rejects_simple_content_type(self):
		decision = self.evaluate(
			self.make_request(
				headers={
					"Origin": "https://crm.pixelwand.io",
					"Sec-Fetch-Site": "same-origin",
				},
				content_type="text/plain",
			)
		)
		self.assertEqual(decision.reason, DenialReason.SIMPLE_CONTENT_TYPE)

	def test_bearer_request_uses_its_own_auth_policy(self):
		decision = self.evaluate(
			self.make_request(headers={"Authorization": "Bearer opaque-token"}),
			user="Guest",
			mechanism="bearer",
		)
		self.assertTrue(decision.allowed)

	def guest_headers(self):
		return {
			"Origin": "https://crm.pixelwand.io",
			"Sec-Fetch-Site": "same-origin",
		}

	def test_codebase_guest_method_needs_no_config_entry(self):
		decision = self.evaluate(
			self.make_request(path=self.GUEST_PATH, headers=self.guest_headers()),
			user="Guest",
			mechanism="guest",
		)
		self.assertTrue(decision.allowed)

	def test_codebase_authed_method_still_denies_guest(self):
		decision = self.evaluate(
			self.make_request(path=self.AUTHED_PATH, headers=self.guest_headers()),
			user="Guest",
			mechanism="guest",
		)
		self.assertEqual(decision.reason, DenialReason.UNKNOWN_AUTH_MECHANISM)

	def test_login_cmd_keeps_auth_error_instead_of_policy_denial(self):
		decision = self.evaluate(
			self.make_request(path="/api/method/login", headers=self.guest_headers()),
			user="Guest",
			mechanism="guest",
		)
		self.assertTrue(decision.allowed)

	def test_builtin_upload_path_needs_no_multipart_config(self):
		decision = self.evaluate(
			self.make_request(
				path="/api/method/upload_file",
				headers=self.guest_headers(),
				content_type="multipart/form-data",
			),
			user="test@example.com",
			mechanism="session",
		)
		self.assertTrue(decision.allowed)

	def test_other_multipart_paths_still_need_config(self):
		decision = self.evaluate(
			self.make_request(
				headers=self.guest_headers(),
				content_type="multipart/form-data",
			),
			user="test@example.com",
			mechanism="session",
		)
		self.assertEqual(decision.reason, DenialReason.SIMPLE_CONTENT_TYPE)
