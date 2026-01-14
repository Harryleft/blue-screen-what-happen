"""
Configuration management for BSOD Analyzer.

Loads settings from environment variables and .env file.
"""

import os
from pathlib import Path
from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict
from dotenv import load_dotenv


class Config(BaseSettings):
    """Application configuration."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # AI configuration
    zhipu_api_key: Optional[str] = None
    ai_model: str = "glm-4.7"
    ai_max_tokens: int = 2048

    # Database configuration
    database_path: str = "~/.bsod_analyzer/crashes.db"

    # Logging configuration
    log_level: str = "INFO"
    log_file: Optional[str] = None

    # Analysis configuration
    default_dump_dir: str = "C:/Windows/Minidump"
    max_stack_frames: int = 10
    confidence_threshold: float = 0.6

    def get_database_path(self) -> Path:
        """Get expanded database path."""
        return Path(self.database_path).expanduser()

    def get_ai_config(self) -> dict:
        """Get AI configuration for provider."""
        return {
            "api_key": self.zhipu_api_key,
            "model": self.ai_model,
            "max_tokens": self.ai_max_tokens,
        }


# Global config instance
_config: Optional[Config] = None


def get_config() -> Config:
    """Get global configuration instance."""
    global _config
    if _config is None:
        load_dotenv()
        _config = Config()
    return _config


def reload_config() -> Config:
    """Reload configuration from environment."""
    global _config
    load_dotenv(override=True)
    _config = Config()
    return _config
