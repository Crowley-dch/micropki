
import pytest
import tempfile
from pathlib import Path
import sys
from unittest.mock import patch

from micropki.cli import (
    validate_key_type,
    validate_key_size,
    validate_validity_days,
    validate_passphrase_file,
    validate_out_dir,
    read_passphrase,
    create_parser
)


class TestCLI:

    def test_validate_key_type_valid(self):
        assert validate_key_type('rsa') == 'rsa'
        assert validate_key_type('ecc') == 'ecc'

    def test_validate_key_type_invalid(self):
        with pytest.raises(Exception):
            validate_key_type('invalid')

    def test_validate_key_size_valid(self):
        assert validate_key_size('4096') == 4096
        assert validate_key_size('384') == 384

    def test_validate_key_size_invalid(self):
        with pytest.raises(Exception):
            validate_key_size('abc')

        with pytest.raises(Exception):
            validate_key_size('-1024')

    def test_validate_validity_days(self):
        assert validate_validity_days('365') == 365
        assert validate_validity_days('3650') == 3650

        with pytest.raises(Exception):
            validate_validity_days('-10')

    def test_validate_passphrase_file(self):
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("test-password")
            passphrase_file = f.name

        try:
            result = validate_passphrase_file(passphrase_file)
            assert str(result) == passphrase_file

            with pytest.raises(Exception):
                validate_passphrase_file("nonexistent.txt")

        finally:
            Path(passphrase_file).unlink()

    def test_validate_out_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Существующая директория
            result = validate_out_dir(tmpdir)
            assert str(result) == tmpdir

            new_dir = Path(tmpdir) / "new"
            result = validate_out_dir(str(new_dir))
            assert str(result) == str(new_dir)

    def test_read_passphrase(self):
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(b"test-password\n")
            passphrase_file = f.name

        try:
            passphrase = read_passphrase(Path(passphrase_file))
            assert passphrase == b"test-password"  # без \n
        finally:
            Path(passphrase_file).unlink()

    def test_create_parser(self):
        parser = create_parser()
        assert parser is not None

        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("pass")
            passphrase_file = f.name

        try:
            args = parser.parse_args([
                'ca-init',
                '--subject', '/CN=Test',
                '--key-type', 'rsa',
                '--key-size', '4096',
                '--passphrase-file', passphrase_file
            ])

            assert args.command == 'ca-init'
            assert args.subject == '/CN=Test'
            assert args.key_type == 'rsa'
            assert args.key_size == 4096

        finally:
            Path(passphrase_file).unlink()