from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application configuration using pydantic-settings.

    The database URL defaults to the local PostgreSQL instance:
    postgresql://kali:kali@localhost/recondb
    """

    database_url: str = "postgresql://kali:kali@localhost/recondb"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()

