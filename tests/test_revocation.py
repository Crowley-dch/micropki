import pytest
import tempfile
import os
from pathlib import Path

from micropki.revocation import (
    get_reason_code,
    get_reason_string,
    revoke_certificate,
    RevocationReason
)
from micropki.database import CertificateDatabase


class TestRevocation:

    def test_reason_code_mapping(self):
        assert get_reason_code('keyCompromise') == RevocationReason.KEY_COMPROMISE
        assert get_reason_code('cACompromise') == RevocationReason.CA_COMPROMISE
        assert get_reason_code('superseded') == RevocationReason.SUPERSEDED
        assert get_reason_code('unspecified') == RevocationReason.UNSPECIFIED

    def test_invalid_reason(self):
        with pytest.raises(ValueError):
            get_reason_code('invalid_reason')

    def test_reason_string_conversion(self):
        code = get_reason_code('keyCompromise')
        reason_str = get_reason_string(code)
        assert reason_str == 'keycompromise' or reason_str == 'keyCompromise'

    @pytest.fixture
    def db_with_cert(self):
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = f.name

        db = CertificateDatabase(db_path)
        db.init_schema()

        cert_data = {
            'serial_hex': '2A7F',
            'subject': 'CN=Test Cert',
            'issuer': 'CN=Test CA',
            'not_before': '2026-01-01T00:00:00',
            'not_after': '2027-01-01T00:00:00',
            'cert_pem': '-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----',
            'status': 'valid'
        }
        db.insert_certificate(cert_data)

        yield db

        db.close()
        os.unlink(db_path)

    def test_revoke_certificate(self, db_with_cert):
        success = revoke_certificate(db_with_cert, '2A7F', 'keyCompromise', force=False)
        assert success is True

        cert = db_with_cert.get_certificate_by_serial('2A7F')
        assert cert['status'] == 'revoked'
        assert cert['revocation_reason'] == 'keycompromise'

    def test_revoke_nonexistent_certificate(self, db_with_cert):
        with pytest.raises(ValueError, match="не найден"):
            revoke_certificate(db_with_cert, 'FFFF', 'unspecified', force=False)

    def test_revoke_already_revoked(self, db_with_cert):
        revoke_certificate(db_with_cert, '2A7F', 'keyCompromise', force=False)

        with pytest.raises(ValueError, match="уже отозван"):
            revoke_certificate(db_with_cert, '2A7F', 'superseded', force=False)

    def test_revoke_already_revoked_with_force(self, db_with_cert):
        revoke_certificate(db_with_cert, '2A7F', 'keyCompromise', force=False)
        success = revoke_certificate(db_with_cert, '2A7F', 'superseded', force=True)
        assert success is True

        cert = db_with_cert.get_certificate_by_serial('2A7F')
        assert cert['revocation_reason'] == 'superseded'