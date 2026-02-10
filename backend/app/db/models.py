from datetime import datetime

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class ScopeTarget(Base):
    """
    Database model for allowed scan targets (IP addresses or domain names).
    """

    __tablename__ = "scope_targets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    target: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    added_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
    )

