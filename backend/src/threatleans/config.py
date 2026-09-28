from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parents[3]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="THREATLEANS_", env_file=ROOT / ".env", extra="ignore")
    database_url: str = "sqlite:///data/runtime/threatleans.db"
    data_dir: Path = ROOT / "data"
    host: str = "127.0.0.1"
    port: int = 8000
    mode: str = "evidence"
    embedding_model: str = "BAAI/bge-small-en-v1.5"
    dense_enabled: bool = False
    qdrant_url: str = ""
    auth_required: bool = False
    cookie_secure: bool = False
    admin_username: str = "admin"
    admin_password: str = ""
    allowed_origins: list[str] = Field(
        default_factory=lambda: [
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:8000",
            "http://127.0.0.1:8000",
        ]
    )
    online_verification: bool = False
    query_deadline_seconds: int = 60
    history_retention_days: int = 30
    demo_faults_enabled: bool = False
    openai_api_key: str = ""
    openai_model: str = ""
    anthropic_api_key: str = ""
    anthropic_model: str = ""
    ollama_url: str = "http://127.0.0.1:11434"
    ollama_model: str = ""
    nvd_api_key: str = ""

    @property
    def resolved_data_dir(self) -> Path:
        return self.data_dir if self.data_dir.is_absolute() else ROOT / self.data_dir

    @property
    def resolved_database_url(self) -> str:
        if self.database_url.startswith("sqlite:///data/"):
            return "sqlite:///" + (ROOT / self.database_url.removeprefix("sqlite:///")).as_posix()
        return self.database_url


@lru_cache
def get_settings() -> Settings:
    return Settings()
