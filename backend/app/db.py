from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from .config import DBPATH
from .models import Base

engine = create_engine(
    f"sqlite:///{DBPATH}",
    pool_pre_ping=True, pool_recycle=3600,
    connect_args={"check_same_thread": False},
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
    _run_migrations()


def _run_migrations() -> None:
    alters = [
        ("devices", "token",            "TEXT DEFAULT ''"),
        ("devices", "sim1signal",       "INTEGER DEFAULT 0"),
        ("devices", "sim2signal",       "INTEGER DEFAULT 0"),
        ("devices", "firmware_version", "VARCHAR(64) DEFAULT ''"),
    ]
    with engine.connect() as conn:
        for table, col, coltype in alters:
            rows = conn.execute(text(f"PRAGMA table_info({table})")).fetchall()
            cols = [r[1] for r in rows]
            if col not in cols:
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col} {coltype}"))
        conn.execute(text("UPDATE devices SET mac = NULL WHERE mac = ''"))
        conn.commit()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
