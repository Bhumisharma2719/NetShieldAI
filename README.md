# NetShield AI

NetShield AI is a full-stack cybersecurity monitoring platform that captures live network packets, analyzes traffic with heuristics and ML-based scoring, and streams real-time packet insights to a browser dashboard.

The system is containerized with Docker and consists of:

- a FastAPI backend that performs live packet sniffing and risk classification
- a React + Vite frontend for the analyst dashboard
- a PostgreSQL database for application data and user management

## Project Overview

NetShield AI continuously monitors live network activity, assigns a risk score to packets, and labels traffic as `SAFE`, `SUSPICIOUS`, or `HIGH-RISK`. The backend exposes live traffic through `/api/live-traffic`, which powers the real-time dashboard UI.

## Key Features

- Live packet sniffing using Scapy
- Real-time risk analysis and threat labeling
- ML-assisted packet scoring
- Live dashboard streaming via `/api/live-traffic`
- Role-based access for admin and analyst users
- Security audit export and threat log download

## Tech Stack

### Backend

- FastAPI
- Scapy
- PostgreSQL
- SQLAlchemy
- Scikit-learn
- Python

### Frontend

- React
- Vite
- JavaScript
- CSS

### Infrastructure

- Docker
- Docker Compose

## Prerequisites

Before running the project, make sure you have:

- Docker installed
- Docker Compose installed

You do not need to manually install Python, Node.js, or PostgreSQL if you are running the project through Docker.

## Setup and Run

1. Clone or open the project folder.
2. From the repository root, run:

```bash
docker compose up --build
```

3. Wait for the containers to start.
4. Open the frontend dashboard in your browser:

```bash
http://localhost:3000
```

5. The backend API will be available at:

```bash
http://localhost:8000
```

## Notes

- The backend starts the live sniffer automatically on startup.
- The dashboard polls the backend for live traffic updates.
- If no real packets are available, the feed will remain idle until traffic is detected.

## Project Structure

- `backend/` - FastAPI application, live sniffer, services, and ML core
- `frontend/` - React dashboard UI
- `docker-compose.yml` - Docker orchestration for backend, frontend, and PostgreSQL

