"""Configuration for the security knowledge graph backend."""

from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    host: str = Field(default="0.0.0.0")
    port: int = Field(default=8000)
    cors_origins: list[str] = Field(default=["http://localhost:5173", "http://localhost:3000"])
    max_file_size_kb: int = Field(default=500)
    max_files: int = Field(default=5000)
    git_clone_timeout: int = Field(default=120)

    model_config = {"env_prefix": "SKG_"}


settings = Settings()
