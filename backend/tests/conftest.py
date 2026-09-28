import os
from pathlib import Path

os.environ["THREATLEANS_DATABASE_URL"] = "sqlite:///" + str(Path(__file__).parents[2] / "tmp" / "test.db")
os.environ["THREATLEANS_AUTH_REQUIRED"] = "false"
os.environ["THREATLEANS_DENSE_ENABLED"] = "false"
