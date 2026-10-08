from unittest.mock import patch

import frappe
from frappe.integrations.utils import OAuth2DynamicClientMetadata, create_new_oauth_client
from frappe.tests import IntegrationTestCase


class TestOAuthDynamicClientRoles(IntegrationTestCase):
	def test_registered_client_allows_website_users_and_requires_consent(self) -> None:
		metadata = OAuth2DynamicClientMetadata.model_validate({
			"client_name": "OAuth role regression",
			"redirect_uris": ["http://127.0.0.1:19876/callback"],
			"token_endpoint_auth_method": "none",
		})
		client = create_new_oauth_client(metadata)
		client.reload()
		self.assertEqual([entry.role for entry in client.allowed_roles], ["All"])
		self.assertFalse(client.skip_authorization)
		with patch("frappe.get_roles", return_value=["All"]):
			self.assertTrue(client.user_has_allowed_role())

	def test_manual_client_keeps_desk_role_default(self) -> None:
		client = frappe.get_doc({
			"doctype": "OAuth Client",
			"app_name": "Manual OAuth role regression",
			"grant_type": "Authorization Code",
			"response_type": "Code",
			"redirect_uris": "http://127.0.0.1:19876/callback",
			"default_redirect_uri": "http://127.0.0.1:19876/callback",
			"scopes": "all",
		}).insert(ignore_permissions=True)
		client.reload()
		self.assertEqual([entry.role for entry in client.allowed_roles], ["Desk User"])
		with patch("frappe.get_roles", return_value=["All"]):
			self.assertFalse(client.user_has_allowed_role())
