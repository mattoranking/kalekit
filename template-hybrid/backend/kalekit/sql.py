from sqlalchemy.dialects import postgresql
from sqlalchemy.sql import Delete, Select, Update, delete, func, select, update

Insert = postgresql.Insert
insert = postgresql.insert


__all__ = [
    "select",
    "insert",
    "update",
    "delete",
    "func",
    "Select",
    "Insert",
    "Update",
    "Delete",
]
