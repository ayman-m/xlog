import logging
import json
import re
import logging.handlers
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request
from starlette.responses import Response

from .config import Config


class CEFLogFormatter(logging.Formatter):
    def __init__(self, vendor, product, version, signature_id):
        super().__init__()
        self.vendor = vendor
        self.product = product
        self.version = version
        self.signature_id = signature_id

    def format(self, record):
        cef_header = f"CEF:0|{self.vendor}|{self.product}|{self.version}|{self.signature_id}|{record.msg}|" \
                     f"{record.levelno}|"
        cef_extension = "|".join(f"{k}={v}" for k, v in record.__dict__.items())
        return f"{cef_header}{cef_extension}"


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        match = re.match(r"(\d+)\s*(\w+)", Config.LOGGING_STORAGE_SIZE, re.IGNORECASE)
        if not match:
            raise ValueError("Invalid max size in config file")
        max_size, unit = match.groups()
        if unit.lower() == "kb" or unit.lower() == "k":
            max_size_bytes = int(max_size) * 1024
        elif unit.lower() == "mb" or unit.lower() == "m":
            max_size_bytes = int(max_size) * 1024 * 1024
        elif unit.lower() == "gb" or unit.lower() == "g":
            max_size_bytes = int(max_size) * 1024 * 1024 * 1024
        else:
            raise ValueError(f"Unknown unit '{unit}' in config file")
        audit_rotation_handler = logging.handlers.RotatingFileHandler(
            f"{Config.LOGGING_DIR}/request_audit.log",
            maxBytes=max_size_bytes,
            backupCount=5,
        )
        audit_rotation_handler.setFormatter(CEFLogFormatter(vendor='Xlog', product='Backend', version='1.0',
                                                            signature_id='0'))
        request_audit_logger = logging.getLogger("request_audit")
        request_audit_logger.setLevel(logging.INFO)
        request_audit_logger.addHandler(audit_rotation_handler)

    @classmethod
    async def set_body(cls, request: Request):
        receive_ = await request._receive()

        async def receive():
            return receive_

        request._receive = receive

    async def dispatch(self, request: Request, call_next) -> Response:
        await self.set_body(request)
        if request.method.lower() == "post":
            json_body = await request.json()
            body_str = json.dumps(json_body)
            truncated_body = body_str[:Config.LOGGING_TRUNCATE_LIMIT] + "..." if \
                len(body_str) > Config.LOGGING_TRUNCATE_LIMIT else body_str
            request_logger = logging.getLogger("request_audit")
            request_logger.info(
                f"{request.method} {request.url.path} {request.client.host} {truncated_body}"
            )
        response = await call_next(request)
        return response
