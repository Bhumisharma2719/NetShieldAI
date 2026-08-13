from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.endpoints import admin, live_traffic, predict
from app.core.config import settings
from app.db.postgres import close_postgres_connection, connect_to_postgres
from app.routers import auth, traffic
from app.services.seed import seed_default_users
from app.services.live_traffic_store import clear_live_capture_storage
from ml_core.live_sniffer import start_live_sniffer_background


@asynccontextmanager
async def lifespan(app: FastAPI):
    await connect_to_postgres()
    if settings.seed_default_users:
        await seed_default_users()

    clear_live_capture_storage()
    app.state.live_sniffer = start_live_sniffer_background(
        getattr(settings, "sniffer_iface", None) or None
    )
    yield
    live_sniffer = getattr(app.state, "live_sniffer", None)
    if live_sniffer is not None:
        live_sniffer.stop()
    await close_postgres_connection()


app = FastAPI(title=settings.app_name, lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix=settings.api_prefix)
app.include_router(traffic.router, prefix=settings.api_prefix)
app.include_router(predict.router, prefix=settings.api_prefix)
app.include_router(live_traffic.router, prefix=settings.api_prefix)
app.include_router(admin.router, prefix=settings.api_prefix)


@app.get("/")
async def root():
    return {"message": "NetShield AI backend is running"}


@app.get(f"{settings.api_prefix}/health")
async def health_check():
    return {"status": "ok"}
