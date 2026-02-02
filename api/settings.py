from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    pulumi_access_token: str = ""
    pulumi_org: str = ""
    pulumi_project: str = ""

    git_repo_url: str = ""
    git_repo_branch: str = "main"
    git_repo_dir: str = "."
    github_token: str = ""

    aws_access_key_id: str = ""
    aws_secret_access_key: str = ""
    aws_region: str = "us-east-1"

    config_storage_path: str = "config"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()