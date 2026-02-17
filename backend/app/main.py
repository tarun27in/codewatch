"""Security Knowledge Graph — FastAPI backend."""

import logging
import sys

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import settings
from .routers import scan, graph, browse, source, cve, remediate

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
    stream=sys.stdout,
)

app = FastAPI(
    title="Security Knowledge Graph",
    description="Scan any codebase and visualize its security knowledge graph",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan.router)
app.include_router(graph.router)
app.include_router(browse.router)
app.include_router(source.router)
app.include_router(cve.router)
app.include_router(remediate.router)


@app.get("/")
async def root():
    return {"service": "security-knowledge-graph", "version": "0.1.0", "status": "running"}
