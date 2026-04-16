from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, List, Dict, Any

from .revocation import get_reason_code


class CRLGenerator:

    def __init__(self, ca_cert: x509.Certificate, ca_private_key, db=None):

        self.ca_cert = ca_cert
        self.ca_private_key = ca_private_key
        self.db = db

        if isinstance(self.ca_private_key, rsa.RSAPrivateKey):
            self.signature_hash = hashes.SHA256()
        else:
            self.signature_hash = hashes.SHA384()

    def get_crl_number(self, ca_subject: str) -> int:
        if self.db:
            conn = self.db._get_connection()
            cursor = conn.cursor()

            cursor.execute(
                "SELECT crl_number FROM crl_metadata WHERE ca_subject = ?",
                (ca_subject,)
            )
            row = cursor.fetchone()

            if row:
                return row[0] + 1
            else:
                now = datetime.now(timezone.utc).isoformat()
                cursor.execute("""
                    INSERT INTO crl_metadata (ca_subject, crl_number, last_generated, next_update, crl_path)
                    VALUES (?, ?, ?, ?, ?)
                """, (ca_subject, 1, now, now, ""))
                conn.commit()
                return 1
        return 1

    def save_crl_number(self, ca_subject: str, crl_number: int,
                        next_update: datetime, crl_path: str):
        if self.db:
            conn = self.db._get_connection()
            cursor = conn.cursor()

            now = datetime.now(timezone.utc).isoformat()

            cursor.execute("""
                INSERT OR REPLACE INTO crl_metadata 
                (ca_subject, crl_number, last_generated, next_update, crl_path)
                VALUES (?, ?, ?, ?, ?)
            """, (ca_subject, crl_number, now, next_update.isoformat(), crl_path))

            conn.commit()

    def get_revoked_certificates(self) -> List[Dict[str, Any]]:
        if not self.db:
            return []

        issuer_dn = str(self.ca_cert.subject)
        all_revoked = self.db.list_certificates(status='revoked')

        return [c for c in all_revoked if c['issuer'] == issuer_dn]

    def generate_crl(self, next_update_days: int = 7,
                     crl_number: Optional[int] = None) -> tuple:

        now = datetime.now(timezone.utc)
        next_update = now + timedelta(days=next_update_days)

        revoked_certs = self.get_revoked_certificates()

        builder = x509.CertificateRevocationListBuilder()
        builder = builder.issuer_name(self.ca_cert.subject)
        builder = builder.last_update(now)
        builder = builder.next_update(next_update)

        for revoked in revoked_certs:
            serial = int(revoked['serial_hex'], 16)

            rev_date_str = revoked.get('revocation_date')
            if rev_date_str is None:
                rev_date = datetime.now(timezone.utc)
            elif isinstance(rev_date_str, str):
                rev_date = datetime.fromisoformat(rev_date_str)
            else:
                rev_date = rev_date_str

            if not isinstance(rev_date, datetime):
                rev_date = datetime.now(timezone.utc)

            revoked_builder = x509.RevokedCertificateBuilder()
            revoked_builder = revoked_builder.serial_number(serial)
            revoked_builder = revoked_builder.revocation_date(rev_date)
            if revoked.get('revocation_reason'):
                reason_code = get_reason_code(revoked['revocation_reason'])
                revoked_builder = revoked_builder.add_extension(
                    x509.CRLReason(reason_code),
                    critical=False
                )

            builder = builder.add_revoked_certificate(revoked_builder.build())

        ski = self.ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        aki = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski.value)
        builder = builder.add_extension(aki, critical=False)

        if crl_number is None:
            crl_number = self.get_crl_number(str(self.ca_cert.subject))

        builder = builder.add_extension(
            x509.CRLNumber(crl_number),
            critical=False
        )

        crl = builder.sign(
            private_key=self.ca_private_key,
            algorithm=self.signature_hash,
            backend=default_backend()
        )

        return crl, crl_number, next_update
    def save_crl(self, crl: x509.CertificateRevocationList,
                 output_path: Path, ca_name: str) -> bool:

        # Конвертируем в PEM
        crl_pem = crl.public_bytes(serialization.Encoding.PEM)

        output_path.write_bytes(crl_pem)

        return True


def generate_crl_for_ca(db, ca_cert_path: Path, ca_key_path: Path,
                        ca_passphrase: bytes, ca_name: str,
                        out_dir: Path, next_update_days: int = 7) -> Path:

    from .crypto_utils import load_encrypted_private_key
    from cryptography import x509

    with open(ca_cert_path, 'rb') as f:
        ca_cert_data = f.read()
    ca_cert = x509.load_pem_x509_certificate(ca_cert_data)

    ca_key = load_encrypted_private_key(ca_key_path, ca_passphrase)

    generator = CRLGenerator(ca_cert, ca_key, db)

    crl, crl_number, next_update = generator.generate_crl(next_update_days)

    crl_dir = out_dir / 'crl'
    crl_dir.mkdir(parents=True, exist_ok=True)

    crl_path = crl_dir / f"{ca_name}.crl.pem"
    generator.save_crl(crl, crl_path, ca_name)

    generator.save_crl_number(str(ca_cert.subject), crl_number, next_update, str(crl_path))

    return crl_path


if __name__ == '__main__':
    print("Тестирование crl.py")
    print("Модуль загружен")