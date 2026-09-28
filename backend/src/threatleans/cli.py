import asyncio
import json
import time
from pathlib import Path

import typer
from sqlalchemy import delete

from .config import get_settings
from .ingest import FEEDS, ingest_cve, ingest_nvd, ingest_source
from .store import DB, Investigation, initialize, now

app = typer.Typer(help="ThreatLeans SOC administration")


@app.command()
def ingest(source: str = "all"):
    """Download official KEV and ATT&CK feeds into the evidence store."""

    async def run():
        for feed in FEEDS if source == "all" else [source]:
            typer.echo(json.dumps(await ingest_source(feed)))

    asyncio.run(run())


@app.command()
def nvd(cve: str):
    """Fetch a specific CVE's versioned NVD metrics."""
    initialize()
    typer.echo(f"Stored {asyncio.run(ingest_nvd(cve.upper()))} NVD records")
    typer.echo(f"Stored {asyncio.run(ingest_cve(cve.upper()))} CVE Program records")


@app.command()
def serve():
    import uvicorn

    s = get_settings()
    uvicorn.run("threatleans.main:app", host=s.host, port=s.port)


@app.command()
def doctor():
    from .gateway import providers
    from .retrieval import retriever

    initialize()
    retriever.refresh()
    typer.echo(
        json.dumps(
            {
                "database": "connected",
                "documents": len(retriever.docs),
                "retrieval": retriever.mode,
                "dense_error": retriever.error,
                "auth": get_settings().auth_required,
                "providers": providers(),
            },
            indent=2,
        )
    )


@app.command()
def worker(interval: int = 86400):
    """Refresh allowlisted public feeds and prune expired investigations on a schedule."""
    from datetime import timedelta

    initialize()
    while True:
        for source in FEEDS:
            try:
                typer.echo(json.dumps(asyncio.run(ingest_source(source))))
            except Exception as exc:
                typer.echo(f"{source} refresh failed: {type(exc).__name__}", err=True)
        with DB.begin() as db:
            db.execute(
                delete(Investigation).where(
                    Investigation.created_at < now() - timedelta(days=get_settings().history_retention_days),
                    Investigation.review_status != "pending",
                )
            )
        time.sleep(max(interval, 300))


@app.command()
def backup(destination: Path):
    """Create a consistent SQLite snapshot; PostgreSQL deployments use pg_dump."""
    import sqlite3

    url = get_settings().resolved_database_url
    if not url.startswith("sqlite:///"):
        raise typer.BadParameter("Use pg_dump for PostgreSQL deployments")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(url.removeprefix("sqlite:///")) as source, sqlite3.connect(destination) as target:
        source.backup(target)
    typer.echo(str(destination.resolve()))


@app.command()
def evaluate(output: Path = Path("reports/evaluation.json")):
    from .evaluation import evaluate as run

    report = asyncio.run(run(output))
    typer.echo(json.dumps({k: v for k, v in report.items() if k != "cases"}, indent=2))


if __name__ == "__main__":
    app()
