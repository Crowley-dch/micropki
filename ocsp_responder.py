"""
HTTP OCSP Responder - RFC 6960
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
from pathlib import Path
import json
import time
import logging
from datetime import datetime

from .ocsp import OCSPResponder
from .database import CertificateDatabase
from .logger import setup_logger


class OCSPHandler(BaseHTTPRequestHandler):
    """HTTP обработчик для OCSP запросов"""

    def __init__(self, *args, **kwargs):
        self.db = kwargs.pop('db', None)
        self.responder = kwargs.pop('responder', None)
        self.logger = kwargs.pop('logger', None)
        super().__init__(*args, **kwargs)

    def log_message(self, format, *args):
        if self.logger:
            self.logger.info(f"[OCSP] {self.address_string()} - {format % args}")

    def do_POST(self):
        """Обрабатывает POST запросы на /ocsp"""
        parsed = urlparse(self.path)

        if parsed.path != '/ocsp':
            self._send_error(404, "Not Found")
            return

        content_type = self.headers.get('Content-Type', '')

        if content_type != 'application/ocsp-request':
            self._send_error(400, "Expected Content-Type: application/ocsp-request")
            return

        content_length = int(self.headers.get('Content-Length', 0))
        if content_length == 0:
            self._send_error(400, "Empty request body")
            return

        request_data = self.rfile.read(content_length)

        start_time = time.time()

        try:
            response_data = self.responder.handle_request(request_data)
            elapsed_ms = (time.time() - start_time) * 1000

            self.send_response(200)
            self.send_header("Content-Type", "application/ocsp-response")
            self.send_header("Content-Length", len(response_data))
            self.end_headers()
            self.wfile.write(response_data)

            self.logger.info(f"OCSP request processed in {elapsed_ms:.2f}ms")

        except Exception as e:
            self.logger.error(f"OCSP request failed: {e}")
            self._send_error(500, "Internal Server Error")

    def do_GET(self):
        """GET запросы - информация о сервере"""
        parsed = urlparse(self.path)

        if parsed.path == '/health':
            self._send_response(200, json.dumps({"status": "ok"}).encode(), "application/json")
        elif parsed.path == '/':
            self._send_response(200, json.dumps({
                "service": "OCSP Responder",
                "endpoints": ["POST /ocsp", "GET /health"]
            }).encode(), "application/json")
        else:
            self._send_error(404, "Not Found")

    def _send_response(self, status_code: int, content: bytes, content_type: str):
        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", len(content))
        self.end_headers()
        self.wfile.write(content)

    def _send_error(self, status_code: int, message: str):
        self._send_response(status_code, message.encode(), "text/plain")


def start_ocsp_server(host: str = "127.0.0.1", port: int = 8081,
                      db_path: str = "./pki/micropki.db",
                      responder_cert_path: str = None,
                      responder_key_path: str = None,
                      ca_cert_path: str = None,
                      cache_ttl: int = 60,
                      log_file: str = None):
    """
    Запускает OCSP responder сервер
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    logger = setup_logger(log_file)
    logger.info(f"Starting OCSP Responder on {host}:{port}")

    # Загружаем CA сертификат
    with open(ca_cert_path, 'rb') as f:
        ca_cert_data = f.read()
    ca_cert = x509.load_pem_x509_certificate(ca_cert_data)
    logger.info(f"CA certificate loaded: {ca_cert.subject}")

    # Загружаем сертификат responder
    with open(responder_cert_path, 'rb') as f:
        responder_cert_data = f.read()
    responder_cert = x509.load_pem_x509_certificate(responder_cert_data)
    logger.info(f"Responder certificate loaded: {responder_cert.subject}")

    # Загружаем ключ responder (незашифрованный)
    with open(responder_key_path, 'rb') as f:
        responder_key_data = f.read()
    responder_key = serialization.load_pem_private_key(responder_key_data, None, default_backend())
    logger.info(f"Responder key loaded")

    # Подключаемся к БД
    db = CertificateDatabase(db_path)
    logger.info(f"Database connected: {db_path}")

    # Создаём OCSP responder
    ocsp = OCSPResponder(db, ca_cert, responder_cert, responder_key)
    logger.info(f"OCSP responder initialized")

    def handler(*args, **kwargs):
        return OCSPHandler(*args, db=db, responder=ocsp, logger=logger, **kwargs)

    server = HTTPServer((host, port), handler)
    logger.info(f"OCSP server listening on http://{host}:{port}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("OCSP server stopped")
        server.shutdown()


if __name__ == '__main__':
    import sys

    print("OCSP Responder module loaded")