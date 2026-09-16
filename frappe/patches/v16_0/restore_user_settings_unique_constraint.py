import frappe

CONSTRAINT_NAME = "__UserSettings_user_doctype_key"
TABLE_NAME = "__UserSettings"


def execute() -> None:
	"""Restore the PostgreSQL conflict target required by user-settings upserts."""
	if frappe.db.db_type != "postgres" or TABLE_NAME not in frappe.db.get_tables():
		return

	if frappe.db.sql(
		"""select 1
		from pg_constraint
		where conrelid = '"__UserSettings"'::regclass
			and conname = %s
			and contype = 'u'""",
		(CONSTRAINT_NAME,),
	):
		return

	# Some legacy PostgreSQL sites predate the unique constraint. Keep the most
	# recently stored physical row for each user/doctype pair before restoring it.
	frappe.db.sql(
		"""delete from "__UserSettings" as older
		using "__UserSettings" as newer
		where older."user" = newer."user"
			and older.doctype = newer.doctype
			and older.ctid < newer.ctid"""
	)
	frappe.db.sql_ddl(
		f'''alter table "{TABLE_NAME}"
		add constraint "{CONSTRAINT_NAME}" unique ("user", doctype)'''
	)
