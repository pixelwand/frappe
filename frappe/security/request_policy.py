"""Origin and Fetch Metadata request policy.

The legacy synchronizer-token policy remains the default. Sites can opt into
``origin_shadow`` to measure the replacement policy without changing request
outcomes, then use ``origin_enforce`` after the client inventory and tests are
complete.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final
from urllib.parse import urlsplit

import frappe
from frappe import _

SAFE_METHODS: Final = frozenset({"GET", "HEAD", "OPTIONS"})
JSON_CONTENT_TYPES: Final = frozenset({"application/json", "application/*+json"})


class PolicyMode(StrEnum):
	TOKEN = "token"
	ORIGIN_SHADOW = "origin_shadow"
	ORIGIN_ENFORCE = "origin_enforce"


class DenialReason(StrEnum):
	MISSING_ORIGIN = "missing_origin"
	MALFORMED_ORIGIN = "malformed_origin"
	UNTRUSTED_ORIGIN = "untrusted_origin"
	CROSS_SITE_FETCH = "cross_site_fetch"
	SIMPLE_CONTENT_TYPE = "simple_content_type"
	UNKNOWN_AUTH_MECHANISM = "unknown_auth_mechanism"
	MISSING_FETCH_METADATA = "missing_fetch_metadata"
	INVALID_NAVIGATION = "invalid_navigation"


@dataclass(frozen=True)
class PolicyDecision:
	allowed: bool
	reason: DenialReason | None = None


def get_policy_mode() -> PolicyMode:
	value = str(frappe.conf.get("csrf_policy", PolicyMode.TOKEN.value)).lower()
	try:
		return PolicyMode(value)
	except ValueError:
		frappe.logger("frappe.security").error("Invalid csrf_policy=%s; using token mode", value)
		return PolicyMode.TOKEN


def _canonical_origin(value: str) -> str | None:
	if not value or value == "null":
		return None

	try:
		parsed = urlsplit(value)
		if (
			parsed.scheme not in {"http", "https"}
			or parsed.username
			or parsed.password
			or parsed.path not in {"", "/"}
			or parsed.query
			or parsed.fragment
		):
			return None
		host = parsed.hostname
		if not host or not host.isascii():
			return None
		port = parsed.port
	except (ValueError, UnicodeError):
		return None

	if (parsed.scheme == "http" and port == 80) or (parsed.scheme == "https" and port == 443):
		port = None
	return f"{parsed.scheme}://{host.lower()}" + (f":{port}" if port else "")


def _trusted_origins() -> set[str]:
	configured = frappe.conf.get("trusted_browser_origins", [])
	if isinstance(configured, str):
		configured = [configured]
	if not isinstance(configured, (list, tuple, set)):
		return set()
	return {
		origin
		for value in configured
		if isinstance(value, str)
		if (origin := _canonical_origin(value)) is not None
	}


def _configured_paths(name: str) -> tuple[str, ...]:
	configured = frappe.conf.get(name, [])
	if isinstance(configured, str):
		configured = [configured]
	if not isinstance(configured, (list, tuple, set)):
		return ()
	return tuple(value for value in configured if isinstance(value, str) and value.startswith("/"))


def _path_is_configured(path: str, setting: str) -> bool:
	return any(path == prefix or path.startswith(prefix.rstrip("/") + "/") for prefix in _configured_paths(setting))


def _is_explicitly_authenticated() -> bool:
	mechanism = getattr(frappe.local, "auth_mechanism", None)
	if mechanism in {"oauth", "api_key", "bearer", "service"}:
		return True
	return frappe.session.user not in {"", "Guest", None}


def _stable_dimension(value: object, default: str) -> str:
	if (
		not isinstance(value, str)
		or not value
		or not value.replace("_", "").replace("-", "").replace(".", "").isalnum()
	):
		return default
	return value


def _route_class(path: str) -> str:
	configured = frappe.conf.get("origin_policy_route_classes", {})
	if isinstance(configured, dict):
		matches = [
			(prefix, label)
			for prefix, label in configured.items()
			if isinstance(prefix, str)
			and (path == prefix or path.startswith(prefix.rstrip("/") + "/"))
			and isinstance(label, str)
		]
		if matches:
			return _stable_dimension(max(matches, key=lambda item: len(item[0]))[1], "unclassified")
	return "unclassified"


def _record_shadow_violation(reason: DenialReason, request) -> None:
	"""Record aggregate dimensions without storing request data or headers."""
	mechanism = _stable_dimension(getattr(frappe.local, "auth_mechanism", None), "unknown")
	route_class = _route_class(request.path or "/")
	key = f"security:origin-policy:{frappe.local.site}:{route_class}:{mechanism}:{reason.value}"
	try:
		current = frappe.cache.get_value(key) or 0
		frappe.cache.set_value(key, int(current) + 1, expires_in_sec=24 * 60 * 60)
	except Exception:
		# Security telemetry must never break a request.
		frappe.logger("frappe.security").debug("Unable to record origin policy telemetry")


def evaluate_request(request) -> PolicyDecision:
	"""Evaluate origin policy for the current request after authentication."""
	if request.method in SAFE_METHODS:
		return PolicyDecision(True)

	# Explicit bearer/API-key authentication does not rely on ambient browser
	# cookies and is governed by its own credential and permission checks. The
	# mechanism is set only after the framework has validated the credential.
	if getattr(frappe.local, "auth_mechanism", None) in {
		"oauth",
		"api_key",
		"bearer",
		"service",
	}:
		return PolicyDecision(True)

	path = request.path or "/"

	origin = frappe.get_request_header("Origin")
	if not origin:
		return PolicyDecision(False, DenialReason.MISSING_ORIGIN)
	canonical = _canonical_origin(origin)
	if canonical is None:
		return PolicyDecision(False, DenialReason.MALFORMED_ORIGIN)
	if canonical not in _trusted_origins():
		return PolicyDecision(False, DenialReason.UNTRUSTED_ORIGIN)

	fetch_site = frappe.get_request_header("Sec-Fetch-Site").lower()
	if not fetch_site and frappe.conf.get("require_fetch_metadata", True):
		return PolicyDecision(False, DenialReason.MISSING_FETCH_METADATA)
	if fetch_site in {"cross-site", "same-site", "none"}:
		return PolicyDecision(False, DenialReason.CROSS_SITE_FETCH)
	if fetch_site and fetch_site != "same-origin":
		return PolicyDecision(False, DenialReason.CROSS_SITE_FETCH)

	navigation_path = _path_is_configured(path, "origin_policy_navigation_paths")
	fetch_mode = frappe.get_request_header("Sec-Fetch-Mode").lower()
	fetch_dest = frappe.get_request_header("Sec-Fetch-Dest").lower()
	if fetch_mode in {"navigate", "no-cors"} and not navigation_path:
		return PolicyDecision(False, DenialReason.INVALID_NAVIGATION)
	if fetch_mode == "navigate" and fetch_dest not in {"", "document"}:
		return PolicyDecision(False, DenialReason.INVALID_NAVIGATION)
	if fetch_dest and fetch_dest != "empty" and not navigation_path:
		return PolicyDecision(False, DenialReason.INVALID_NAVIGATION)

	content_type = (request.mimetype or "").lower()
	if content_type == "multipart/form-data":
		if not _path_is_configured(path, "origin_policy_multipart_paths"):
			return PolicyDecision(False, DenialReason.SIMPLE_CONTENT_TYPE)
	elif not (
		content_type in JSON_CONTENT_TYPES or content_type.endswith("+json")
	) and not _path_is_configured(
		path, "origin_policy_content_type_exempt_paths"
	):
		return PolicyDecision(False, DenialReason.SIMPLE_CONTENT_TYPE)

	if not _is_explicitly_authenticated() and not _path_is_configured(
		path, "origin_policy_guest_paths"
	):
		return PolicyDecision(False, DenialReason.UNKNOWN_AUTH_MECHANISM)

	return PolicyDecision(True)


def enforce_request_policy(request) -> None:
	"""Apply the configured policy after ``validate_auth`` has selected a user."""
	mode = get_policy_mode()
	if mode is PolicyMode.TOKEN:
		return

	decision = evaluate_request(request)
	if decision.allowed:
		return

	assert decision.reason is not None
	if mode is PolicyMode.ORIGIN_SHADOW:
		_record_shadow_violation(decision.reason, request)
		return

	frappe.flags.disable_traceback = True
	frappe.throw(_("Invalid Request"), frappe.CSRFTokenError)


def should_skip_token_validation() -> bool:
	"""Return whether origin enforcement replaces the synchronizer token."""
	return get_policy_mode() is PolicyMode.ORIGIN_ENFORCE
