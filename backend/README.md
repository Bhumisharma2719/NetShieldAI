# NetShield AI Backend

FastAPI backend with PostgreSQL, JWT authentication, role-based users, and Google Identity token login.

## Setup

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
uvicorn app.main:app --reload
```

PostgreSQL should be running locally, and the `netshield_ai` database should exist.

Default local connection:

```env
DATABASE_URL=postgresql+asyncpg://postgres:postgres@localhost:5432/netshield_ai
```

Default seeded users:

- Admin: `admin` / `admin123`
- Analyst: `analyst` / `analyst123`

Change these credentials in `.env` before production use.

## Traffic Dataset

Development CSV:

```text
backend/data/unsw_nb15_sample.csv
```

Regenerate it with:

```bash
cd backend
.venv\Scripts\activate
python scripts\prepare_sample_dataset.py
```

Load CSV rows into PostgreSQL:

```bash
cd backend
.venv\Scripts\activate
python scripts\ingest_network_logs.py
```

The file is UNSW-NB15-shaped sample data for dashboard development. Later, replace it with an official UNSW-NB15 or CICIDS2017 CSV and keep/rename the expected columns: `timestamp`, `src_ip`, `dst_ip`, `proto`, `service`, `state`, `dur`, `spkts`, `dpkts`, `sbytes`, `dbytes`, `rate`, `attack_cat`, `label`.

Traffic API:

- `GET /api/traffic/summary`
- `GET /api/traffic/records?offset=0&limit=50`
