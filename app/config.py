import os


class Config:
    WORKERS_NUMBER = os.getenv("WORKERS_NUMBER", "25")
    LOGGING_DIR = os.getenv("LOGGING_DIR", "logs")
    LOGGING_STORAGE_SIZE = os.getenv("LOGGING_STORAGE_SIZE", "10M")
    LOGGING_TRUNCATE_LIMIT = os.getenv("LOGGING_TRUNCATE_LIMIT", "100")
    XSIAM_MANDATORY_PARSED_FIELDS = os.getenv(
        "XSIAM_MANDATORY_PARSED_FIELDS",
        "remote_ip,remote_port,local_ip,local_port,event_timestamp,severity,alert_name",
    )
    XSIAM_OPTIONAL_PARSED_FIELDS = os.getenv(
        "XSIAM_OPTIONAL_PARSED_FIELDS",
        "alert_description,action_status,local_ip_v6,remote_ip_v6",
    )
