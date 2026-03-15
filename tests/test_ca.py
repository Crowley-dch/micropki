import pytest
import tempfile
from pathlib import Path
import os

from micropki.ca import CertificateAuthority
from micropki.logger import setup_logger


class TestCertificateAuthority:

    def setup_method(self):
        self.temp_dir = tempfile.mkdtemp()
        self.logger = setup_logger()
        self.ca = CertificateAuthority(out_dir=self.temp_dir)
        self.passphrase = b"test-passphrase"

    def test_create_directories(self):
        self.ca.create_directories()

        assert (Path(self.temp_dir) / 'private').exists()
        assert (Path(self.temp_dir) / 'certs').exists()

    def test_check_existing_files(self):
        self.ca.create_directories()

        test_file = Path(self.temp_dir) / 'private' / 'ca.key.pem'
        test_file.write_text("test content")

        assert self.ca.check_existing_files(force=False) is False

        assert self.ca.check_existing_files(force=True) is True

    def test_init_root_ca_without_force(self):
        self.ca.create_directories()

        self.ca.init_root_ca(
            subject="/CN=Test CA",
            key_type="rsa",
            key_size=4096,
            passphrase=b"test",
            validity_days=365,
            force=False
        )

        with pytest.raises(FileExistsError, match="Файлы уже существуют"):
            self.ca.init_root_ca(
                subject="/CN=Test CA",
                key_type="rsa",
                key_size=4096,
                passphrase=b"test",
                validity_days=365,
                force=False
            )

    def test_init_root_ca_with_force(self):
        self.ca.create_directories()

        files1 = self.ca.init_root_ca(
            subject="/CN=Test CA",
            key_type="rsa",
            key_size=4096,
            passphrase=b"test",
            validity_days=365,
            force=False
        )

        files2 = self.ca.init_root_ca(
            subject="/CN=Test CA",
            key_type="rsa",
            key_size=4096,
            passphrase=b"test",
            validity_days=365,
            force=True
        )

        assert Path(files2['key_path']).exists()
        assert Path(files2['cert_path']).exists()

    def test_init_root_ca_rsa(self):
        self.ca.create_directories()

        files = self.ca.init_root_ca(
            subject="/CN=Test Root CA",
            key_type="rsa",
            key_size=4096,
            passphrase=self.passphrase,
            validity_days=365
        )

        assert Path(files['key_path']).exists()
        assert Path(files['cert_path']).exists()
        assert Path(files['policy_path']).exists()

        # Проверяем права доступа (на Unix)
        if os.name != 'nt':  # не Windows
            assert oct(Path(files['key_path']).stat().st_mode)[-3:] == '600'

    def test_init_root_ca_ecc(self):
        self.ca.create_directories()

        files = self.ca.init_root_ca(
            subject="/CN=Test ECC Root CA",
            key_type="ecc",
            key_size=384,
            passphrase=self.passphrase,
            validity_days=365
        )

        assert Path(files['key_path']).exists()
        assert Path(files['cert_path']).exists()

    def test_policy_file_content(self):
        self.ca.create_directories()

        subject = "/CN=Policy Test CA"
        files = self.ca.init_root_ca(
            subject=subject,
            key_type="rsa",
            key_size=4096,
            passphrase=self.passphrase,
            validity_days=365
        )

        policy_path = Path(files['policy_path'])
        content = policy_path.read_text(encoding='utf-8')

        assert subject in content
        assert "RSA" in content
        assert "4096" in content
        assert "Version: 1.0" in content