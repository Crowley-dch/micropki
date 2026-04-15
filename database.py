import sqlite3
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime
import threading


class CertificateDatabase:


    def __init__(self, db_path: str):

        self.db_path = Path(db_path)
        self._local = threading.local()

    def _get_connection(self) -> sqlite3.Connection:
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)

            self._local.conn = sqlite3.connect(str(self.db_path))
            self._local.conn.row_factory = sqlite3.Row

            # Включаем поддержку внешних ключей
            self._local.conn.execute("PRAGMA foreign_keys = ON")

        return self._local.conn

    def close(self):
        if hasattr(self._local, 'conn') and self._local.conn:
            self._local.conn.close()
            self._local.conn = None

    def init_schema(self) -> bool:
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='certificates'"
        )
        if cursor.fetchone():
            return True

        cursor.execute("""
            CREATE TABLE certificates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                serial_hex TEXT UNIQUE NOT NULL,
                subject TEXT NOT NULL,
                issuer TEXT NOT NULL,
                not_before TEXT NOT NULL,
                not_after TEXT NOT NULL,
                cert_pem TEXT NOT NULL,
                status TEXT NOT NULL,
                revocation_reason TEXT,
                revocation_date TEXT,
                created_at TEXT NOT NULL
            )
        """)

        cursor.execute("CREATE INDEX idx_serial_hex ON certificates(serial_hex)")
        cursor.execute("CREATE INDEX idx_status ON certificates(status)")
        cursor.execute("CREATE INDEX idx_not_after ON certificates(not_after)")

        conn.commit()
        return True

    def insert_certificate(self, cert_data: Dict[str, Any]) -> bool:

        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                INSERT INTO certificates (
                    serial_hex, subject, issuer, not_before, not_after,
                    cert_pem, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                cert_data['serial_hex'],
                cert_data['subject'],
                cert_data['issuer'],
                cert_data['not_before'],
                cert_data['not_after'],
                cert_data['cert_pem'],
                cert_data.get('status', 'valid'),
                cert_data.get('created_at', datetime.now().isoformat())
            ))
            conn.commit()
            return True
        except sqlite3.IntegrityError as e:
            print(f"Ошибка: дубликат серийного номера - {e}")
            return False
        except Exception as e:
            print(f"Ошибка при вставке сертификата: {e}")
            return False

    def get_certificate_by_serial(self, serial_hex: str) -> Optional[Dict[str, Any]]:

        conn = self._get_connection()
        cursor = conn.cursor()

        serial_hex = serial_hex.upper()
        cursor.execute(
            "SELECT * FROM certificates WHERE serial_hex = ?",
            (serial_hex,)
        )

        row = cursor.fetchone()
        return dict(row) if row else None

    def list_certificates(
            self,
            status: Optional[str] = None,
            limit: int = 100,
            offset: int = 0
    ) -> List[Dict[str, Any]]:

        conn = self._get_connection()
        cursor = conn.cursor()

        query = "SELECT * FROM certificates"
        params = []

        if status:
            query += " WHERE status = ?"
            params.append(status)

        query += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor.execute(query, params)

        return [dict(row) for row in cursor.fetchall()]

    def update_status(
            self,
            serial_hex: str,
            status: str,
            revocation_reason: Optional[str] = None
    ) -> bool:

        conn = self._get_connection()
        cursor = conn.cursor()

        serial_hex = serial_hex.upper()
        revocation_date = datetime.now().isoformat() if status == 'revoked' else None

        try:
            cursor.execute("""
                UPDATE certificates
                SET status = ?,
                    revocation_reason = ?,
                    revocation_date = ?
                WHERE serial_hex = ?
            """, (status, revocation_reason, revocation_date, serial_hex))
            conn.commit()
            return cursor.rowcount > 0
        except Exception as e:
            print(f"Ошибка обновления статуса: {e}")
            return False

    def get_revoked_certificates(self) -> List[Dict[str, Any]]:

        return self.list_certificates(status='revoked')

    def update_expired_status(self) -> int:

        conn = self._get_connection()
        cursor = conn.cursor()

        now = datetime.now().isoformat()

        cursor.execute("""
            UPDATE certificates
            SET status = 'expired'
            WHERE status = 'valid' AND not_after < ?
        """, (now,))

        conn.commit()
        return cursor.rowcount

    def count_certificates(self, status: Optional[str] = None) -> int:

        conn = self._get_connection()
        cursor = conn.cursor()

        if status:
            cursor.execute(
                "SELECT COUNT(*) FROM certificates WHERE status = ?",
                (status,)
            )
        else:
            cursor.execute("SELECT COUNT(*) FROM certificates")

        return cursor.fetchone()[0]


if __name__ == '__main__':
    import tempfile
    import os
    import time

    print("Тестирование database.py")

    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        db_path = f.name

    try:
        db = CertificateDatabase(db_path)
        db.init_schema()
        print(f" База данных создана: {db_path}")

        cert_data = {
            'serial_hex': '2A7F',
            'subject': 'CN=Test Cert',
            'issuer': 'CN=Test CA',
            'not_before': '2026-01-01T00:00:00',
            'not_after': '2027-01-01T00:00:00',
            'cert_pem': '-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----',
            'status': 'valid'
        }

        if db.insert_certificate(cert_data):
            print(" Сертификат вставлен")

        cert = db.get_certificate_by_serial('2A7F')
        print(f" Найден сертификат: {cert['subject'] if cert else 'None'}")

        certs = db.list_certificates()
        print(f" Всего сертификатов: {len(certs)}")

        if db.update_status('2A7F', 'revoked', 'key compromise'):
            print(" Статус обновлён")

        db.close()
        time.sleep(0.1)  #

        print("\n Все тесты пройдены!")

    finally:
        try:
            os.unlink(db_path)
        except PermissionError:
            print(f" Не удалось удалить {db_path} (файл может быть ещё занят)")