from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.db.base import Base
from app.db import models as _models  # noqa: F401  # ensure models are imported for metadata


# SQLAlchemy engine configured with the application database URL
engine = create_engine(settings.database_url, future=True)

# Create all tables (for now, simple metadata-driven schema management)
Base.metadata.create_all(bind=engine)

# Factory for database sessions
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine, class_=Session)


def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency that provides a database session.

    Yields:
        A SQLAlchemy Session, properly closed after the request.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

