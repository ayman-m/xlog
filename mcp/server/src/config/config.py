"""Configuration settings for XLog MCP Server."""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Configuration model using Pydantic.
    Loads settings from environment variables.
    """

    # --- XLog Server Settings ---
    xlog_url: str = Field("http://localhost:8000", validation_alias="XLOG_URL")
    xlog_port: int = Field(8000, validation_alias="XLOG_PORT")

    # --- MCP Server Settings ---
    mcp_transport: str = Field("stdio", validation_alias="MCP_TRANSPORT")
    mcp_host: str = Field("0.0.0.0", validation_alias="MCP_HOST")
    mcp_port: int = Field(8080, validation_alias="MCP_PORT")
    mcp_path: str = Field("/api/v1/stream/mcp", validation_alias="MCP_PATH")

    # --- SSL Settings ---
    ssl_cert_file: str | None = Field(None, validation_alias="SSL_CERT_FILE")
    ssl_key_file: str | None = Field(None, validation_alias="SSL_KEY_FILE")
    ssl_cert_pem: str | None = Field(None, validation_alias="SSL_CERT_PEM")
    ssl_key_pem: str | None = Field(None, validation_alias="SSL_KEY_PEM")

    # --- Log Settings ---
    log_level: str = Field("INFO", validation_alias="LOG_LEVEL")
    log_file_path: str | None = Field(None, validation_alias="LOG_FILE_PATH")

    # --- XSIAM PAPI Settings ---
    papi_url_env_key: str = Field("", validation_alias="CORTEX_MCP_PAPI_URL")
    papi_auth_header_key: str = Field("", validation_alias="CORTEX_MCP_PAPI_AUTH_HEADER")
    papi_auth_id_key: str = Field("", validation_alias="CORTEX_MCP_PAPI_AUTH_ID")
    playground_id: str = Field("", validation_alias="PLAYGROUND_ID")
    webhook_endpoint: str | None = Field(None, validation_alias="WEBHOOK_ENDPOINT")
    webhook_key: str | None = Field(None, validation_alias="WEBHOOK_KEY")

    # --- Caldera Settings ---
    caldera_url: str = Field("http://localhost:8888/api/v2/", validation_alias="CALDERA_URL")
    caldera_api_key: str = Field("ADMIN123", validation_alias="CALDERA_API_KEY")

    # --- Technology Stack Settings ---
    technology_stack: str | None = Field(
        None,
        validation_alias="TECHNOLOGY_STACK",
        description="JSON string containing organization's technology stack for log generation"
    )

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


# Global config instance
config = Settings()


def reload_config():
    """Reload the global config instance."""
    global config
    config = Settings()
    return config


def get_config():
    """Get the current config instance."""
    return config
