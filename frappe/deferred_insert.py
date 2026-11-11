import json
from typing import TYPE_CHECKING, Union

import redis

import frappe
from frappe.utils import cstr

if TYPE_CHECKING:
	from frappe.model.document import Document

queue_prefix = "insert_queue_for_"


def deferred_insert(doctype: str, records: list[dict | "Document"] | str):
	if frappe.conf.get("run_background_jobs_inline"):
		return _insert_after_transaction(doctype, records)

	if isinstance(records, dict | list):
		_records = json.dumps(records)
	else:
		_records = records

	try:
		frappe.cache.rpush(f"{queue_prefix}{doctype}", _records)
	except redis.exceptions.ConnectionError:
		for record in records:
			insert_record(record, doctype)


def _insert_after_transaction(doctype: str, records: list[dict | "Document"] | dict | str) -> None:
	"""`run_background_jobs_inline`: no scheduler runs `save_to_db`, so insert the records once the
	current transaction ends and commit them. Rollback counts too: a failed request logs its Error Log
	here and then rolls back."""
	if isinstance(records, str):
		records = json.loads(records)
	if isinstance(records, dict):
		records = [records]
	done = False

	def flush():
		nonlocal done
		if done:
			return
		done = True
		for record in records:
			insert_record(record, doctype)
		frappe.db.commit()

	frappe.db.after_commit.add(flush)
	frappe.db.after_rollback.add(flush)


def save_to_db():
	queue_keys = frappe.cache.get_keys(queue_prefix)
	for key in queue_keys:
		record_count = 0
		queue_key = get_key_name(key)
		doctype = get_doctype_name(key)
		while frappe.cache.llen(queue_key) > 0 and record_count <= 10000:
			records = frappe.cache.lpop(queue_key)
			records = json.loads(records.decode("utf-8"))
			if isinstance(records, dict):
				record_count += 1
				insert_record(records, doctype)
				continue
			for record in records:
				record_count += 1
				insert_record(record, doctype)
				if record_count % 100 == 0:
					frappe.db.commit()

			if record_count % 100 == 0:
				frappe.db.commit()


def insert_record(record: dict | "Document", doctype: str):
	try:
		record.update({"doctype": doctype})
		frappe.get_doc(record).insert()
	except Exception as e:
		frappe.logger().error(f"Error while inserting deferred {doctype} record: {e}")


def get_key_name(key: str) -> str:
	return cstr(key).split("|")[1]


def get_doctype_name(key: str) -> str:
	return cstr(key).split(queue_prefix)[1]
