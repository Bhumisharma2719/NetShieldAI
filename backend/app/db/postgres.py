from sqlalchemy import URL, text
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine

from app.core.config import settings

engine: AsyncEngine | None = None
async_session: async_sessionmaker | None = None


async def connect_to_postgres() -> None:
    global engine, async_session
    database_url = settings.database_url or URL.create(
        "postgresql+asyncpg",
        username=settings.postgres_user,
        password=settings.postgres_password,
        host=settings.postgres_host,
        port=settings.postgres_port,
        database=settings.postgres_db,
    )
    engine = create_async_engine(database_url, pool_pre_ping=True)
    async_session = async_sessionmaker(engine, expire_on_commit=False)
    await create_tables()


async def close_postgres_connection() -> None:
    if engine is not None:
        await engine.dispose()


def get_sessionmaker() -> async_sessionmaker:
    if async_session is None:
        raise RuntimeError("PostgreSQL connection has not been initialized")
    return async_session


async def create_tables() -> None:
    if engine is None:
        raise RuntimeError("PostgreSQL engine has not been initialized")

    async with engine.begin() as connection:
        await connection.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    user_id VARCHAR(120) NOT NULL UNIQUE,
                    role VARCHAR(30) NOT NULL CHECK (role IN ('admin', 'analyst')),
                    password_hash TEXT,
                    email VARCHAR(255) UNIQUE,
                    name VARCHAR(255),
                    provider VARCHAR(50) NOT NULL DEFAULT 'password',
                    is_active BOOLEAN NOT NULL DEFAULT TRUE,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    last_login_at TIMESTAMPTZ
                )
                """
            )
        )
        await connection.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ"))
        await connection.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS network_logs (
                    id INTEGER PRIMARY KEY,
                    timestamp TIMESTAMPTZ NOT NULL,
                    src_ip VARCHAR(64),
                    dst_ip VARCHAR(64),
                    proto VARCHAR(24),
                    service VARCHAR(64),
                    state VARCHAR(24),
                    duration DOUBLE PRECISION,
                    spkts INTEGER,
                    dpkts INTEGER,
                    packets INTEGER,
                    sbytes BIGINT,
                    dbytes BIGINT,
                    bytes BIGINT,
                    rate DOUBLE PRECISION,
                    attack_cat VARCHAR(80),
                    label INTEGER
                )
                """
            )
        )
        await connection.execute(text("CREATE INDEX IF NOT EXISTS idx_network_logs_timestamp ON network_logs (timestamp)"))
        await connection.execute(text("CREATE INDEX IF NOT EXISTS idx_network_logs_attack_cat ON network_logs (attack_cat)"))
