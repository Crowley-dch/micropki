

from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from pathlib import Path
import json
import os
from datetime import datetime

from .database import CertificateDatabase
from .logger import setup_logger, get_logger


class RepositoryHandler(BaseHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        self.db_path = kwargs.pop('db_path', './pki/micropki.db')
        self.cert_dir = kwargs.pop('cert_dir', './pki/certs')
        self.logger = kwargs.pop('logger', None)
        super().__init__(*args, **kwargs)

    def log_message(self, format, *args):
        if self.logger:
            self.logger.info(f"[HTTP] {self.address_string()} - {format % args}")

    def _handle_get_crl(self):

        from urllib.parse import urlparse, parse_qs

        parsed = urlparse(self.path)
        query_params = parse_qs(parsed.query)

        ca_param = query_params.get('ca', ['intermediate'])[0]

        if ca_param == 'root':
            crl_path = Path(self.cert_dir).parent / 'crl' / 'root.crl.pem'
        elif ca_param == 'intermediate':
            crl_path = Path(self.cert_dir).parent / 'crl' / 'intermediate.crl.pem'
        else:
            self._send_error(400, f"Invalid CA parameter: {ca_param}. Use 'root' or 'intermediate'")
            return

        if not crl_path.exists():
            self._send_error(404, f"CRL not found for {ca_param} CA")
            self.logger.warning(f"[HTTP] CRL not found: {crl_path}")
            return

        with open(crl_path, 'rb') as f:
            crl_content = f.read()

        self.send_response(200)
        self.send_header("Content-Type", "application/pkix-crl")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", len(crl_content))

        stat = crl_path.stat()
        self.send_header("Last-Modified", self.date_time_string(stat.st_mtime))
        self.send_header("Cache-Control", "max-age=3600")  # 1 час

        self.end_headers()
        self.wfile.write(crl_content)

        self.logger.info(f"[HTTP] CRL served: {ca_param}.crl.pem")

    def _handle_get_crl_file(self, ca_name: str):

        crl_path = Path(self.cert_dir).parent / 'crl' / f"{ca_name}.crl.pem"

        if not crl_path.exists():
            self._send_error(404, f"CRL not found for {ca_name} CA")
            return

        with open(crl_path, 'rb') as f:
            crl_content = f.read()

        self.send_response(200)
        self.send_header("Content-Type", "application/pkix-crl")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", len(crl_content))
        self.end_headers()
        self.wfile.write(crl_content)

        self.logger.info(f"[HTTP] CRL served: {ca_name}.crl.pem")
    def _send_response(self, status_code: int, content: bytes, content_type: str = "text/plain"):
        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", len(content))
        self.end_headers()
        self.wfile.write(content)

    def _send_error(self, status_code: int, message: str):
        self._send_response(status_code, message.encode('utf-8'))

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        self.logger.info(f"[HTTP] GET {path}")

        if path.startswith('/certificate/'):
            serial = path.split('/')[-1]
            self._handle_get_certificate(serial)

        elif path == '/ca/root':
            self._handle_get_ca('root')

        elif path == '/ca/intermediate':
            self._handle_get_ca('intermediate')

        elif path == '/crl':
            self._handle_get_crl()

        elif path == '/crl/root.crl':
            self._handle_get_crl_file('root')

        elif path == '/crl/intermediate.crl':
            self._handle_get_crl_file('intermediate')

        elif path == '/health':
            self._send_response(200, b'{"status": "ok"}', "application/json")

        elif path == '/' or path == '':
            self._handle_root()

        else:
            self._send_error(404, f"Not Found: {path}")
    def _handle_root(self):
        content = {
            "endpoints": [
                "/certificate/<serial>",
                "/ca/root",
                "/ca/intermediate",
                "/crl",
                "/crl?ca=root",
                "/crl?ca=intermediate",
                "/crl/root.crl",
                "/crl/intermediate.crl",
                "/health"
            ]
        }
        self._send_response(200, json.dumps(content, indent=2).encode('utf-8'), "application/json")

    def _handle_get_certificate(self, serial: str):

        try:
            int(serial, 16)
        except ValueError:
            self._send_error(400, f"Invalid serial number format: {serial}. Expected hex string.")
            return

        db = CertificateDatabase(self.db_path)
        cert = db.get_certificate_by_serial(serial.upper())

        if cert:
            self._send_response(200, cert['cert_pem'].encode('utf-8'), "application/x-pem-file")
            self.logger.info(f"[HTTP] Certificate found: {serial}")
        else:
            self._send_error(404, f"Certificate with serial {serial} not found")
            self.logger.warning(f"[HTTP] Certificate not found: {serial}")

    def _handle_get_ca(self, level: str):

        if level == 'root':
            cert_path = Path(self.cert_dir) / 'ca.cert.pem'
        elif level == 'intermediate':
            cert_path = Path(self.cert_dir) / 'intermediate.cert.pem'
        else:
            self._send_error(400, f"Invalid CA level: {level}")
            return

        if cert_path.exists():
            with open(cert_path, 'rb') as f:
                cert_content = f.read()
            self._send_response(200, cert_content, "application/x-pem-file")
            self.logger.info(f"[HTTP] CA certificate sent: {level}")
        else:
            self._send_error(404, f"{level.capitalize()} CA certificate not found")
            self.logger.warning(f"[HTTP] CA certificate not found: {level}")

    def _handle_get_crl(self):

        self.send_response(501)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(b"CRL generation not yet implemented")
        self.logger.info("[HTTP] CRL endpoint called (not implemented)")


def start_server(host: str = "127.0.0.1", port: int = 8888,
                 db_path: str = "./pki/micropki.db",
                 cert_dir: str = "./pki/certs",
                 log_file: str = None):

    logger = setup_logger(log_file)

    def handler(*args, **kwargs):
        return RepositoryHandler(*args,
                                 db_path=db_path,
                                 cert_dir=cert_dir,
                                 logger=logger,
                                 **kwargs)

    server = HTTPServer((host, port), handler)
    logger.info(f"HTTP сервер запущен на http://{host}:{port}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("HTTP сервер остановлен")
        server.shutdown()


if __name__ == '__main__':
    print("Тестирование repository.py")
    print("Запуск сервера на http://localhost:8888")
    print("Доступные эндпоинты:")
    print("  GET /certificate/<serial> - получить сертификат")
    print("  GET /ca/root - получить корневой CA")
    print("  GET /ca/intermediate - получить промежуточный CA")
    print("  GET /crl - CRL (placeholder)")
    print("  GET /health - проверка состояния")
    print("\nНажмите Ctrl+C для остановки")

    start_server(
        host="127.0.0.1",
        port=8080,
        db_path="./pki/micropki.db",
        cert_dir="./pki/certs"
    )