from datetime import datetime
from uuid import UUID

from sqlalchemy import TIMESTAMP, MetaData, Uuid
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from kalekit.utils.func import generate_uuid, utc_now

my_metadata = MetaData(
    naming_convention={
        "ix": "ix_%(column_0_N_label)s",
        "uq": "%(table_name)s_%(column_0_N_name)s_key",
        "ck": "%(table_name)s_%(constraint_name)s_check",
        "fk": "%(table_name)s_%(column_0_N_name)s_fkey",
        "pk": "%(table_name)s_pkey",
    }
)


class Model(DeclarativeBase):
    __abstract__ = True

    metadata = my_metadata


class TimestampedModel(Model):
    __abstract__ = True

    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), default=utc_now, nullable=False, index=True
    )
    updated_at: Mapped[datetime | None] = mapped_column(
        TIMESTAMP(timezone=True), onupdate=utc_now, nullable=True, default=None
    )
    deleted_at: Mapped[datetime | None] = mapped_column(
        TIMESTAMP(timezone=True), nullable=True, default=None, index=True
    )

    def set_updated_at(self) -> None:
        self.updated_at = utc_now()

    def set_deleted_at(self) -> None:
        self.deleted_at = utc_now()


class IDModel(Model):
    __abstract__ = True

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=generate_uuid)

    def __eq__(self, __value: object) -> bool:
        return isinstance(__value, self.__class__) and self.id == __value.id

    def __hash__(self) -> int:
        return self.id.int

    @classmethod
    def generate_id(cls) -> UUID:
        return generate_uuid()


class RecordModel(IDModel, TimestampedModel):
    __abstract__ = True
