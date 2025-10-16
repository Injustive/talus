from database.base_models import BaseModel
from sqlalchemy import String
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.orm import Mapped, mapped_column, validates
from sqlalchemy import Integer
from sqlalchemy import String, Boolean, DateTime


class Base(DeclarativeBase):
    pass


class TalusBaseModel(BaseModel):
    __tablename__ = "talus_base"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    twitter_token: Mapped[str] = mapped_column(String, nullable=True)
    discord_token: Mapped[str] = mapped_column(String, nullable=True)
    email: Mapped[str] = mapped_column(String, nullable=True)
    bad_email: Mapped[str] = mapped_column(Boolean, default=False)
    bad_twitter_token: Mapped[bool] = mapped_column(Boolean, default=False)
    bad_discord_token: Mapped[bool] = mapped_column(Boolean, default=False)
    twitter_connected: Mapped[bool] = mapped_column(Boolean, default=False)
    discord_connected: Mapped[bool] = mapped_column(Boolean, default=False)
    email_connected: Mapped[bool] = mapped_column(Boolean, default=False)
    sol_wallet: Mapped[str] = mapped_column(String, nullable=True)
    sui_wallet: Mapped[str] = mapped_column(String, nullable=True)
    initials_tasks_completed: Mapped[bool] = mapped_column(Boolean, default=False)
