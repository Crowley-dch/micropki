from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from pathlib import Path
from typing import List, Tuple
import datetime


class ChainValidator:

    def __init__(self):
        self.errors = []
        self.warnings = []

    def validate_chain(self, leaf_cert: x509.Certificate,
                       intermediate_cert: x509.Certificate,
                       root_cert: x509.Certificate) -> Tuple[bool, List[str], List[str]]:

        self.errors = []
        self.warnings = []

        self._verify_signature(leaf_cert, intermediate_cert.public_key(), "leaf", "intermediate")

        self._verify_signature(intermediate_cert, root_cert.public_key(), "intermediate", "root")

        now = datetime.datetime.now(datetime.timezone.utc)
        self._check_validity(leaf_cert, "leaf", now)
        self._check_validity(intermediate_cert, "intermediate", now)
        self._check_validity(root_cert, "root", now)

        self._check_basic_constraints(leaf_cert, is_ca=False)
        self._check_basic_constraints(intermediate_cert, is_ca=True)
        self._check_basic_constraints(root_cert, is_ca=True)

        self._check_key_usage(intermediate_cert, "intermediate")
        self._check_key_usage(root_cert, "root")

        self._check_path_length(intermediate_cert, root_cert)

        return len(self.errors) == 0, self.errors, self.warnings

    def _verify_signature(self, cert: x509.Certificate,
                          issuer_public_key,
                          cert_name: str,
                          issuer_name: str):
        try:
            if isinstance(cert.signature_hash_algorithm, hashes.SHA256):
                issuer_public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    cert.signature_hash_algorithm
                )
            else:
                # Для ECC
                issuer_public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    cert.signature_hash_algorithm
                )
        except Exception as e:
            self.errors.append(f"Подпись {cert_name} -> {issuer_name} недействительна: {e}")
            return False
        return True

    def _check_validity(self, cert: x509.Certificate, name: str, now: datetime.datetime):
        if cert.not_valid_before_utc > now:
            self.errors.append(f"Сертификат {name} еще не действителен (с {cert.not_valid_before_utc})")
        if cert.not_valid_after_utc < now:
            self.errors.append(f"Сертификат {name} истек ({cert.not_valid_after_utc})")

    def _check_basic_constraints(self, cert: x509.Certificate, is_ca: bool):
        try:
            bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
            if is_ca and not bc.value.ca:
                self.errors.append(f"Сертификат должен быть CA, но CA=FALSE")
            if not is_ca and bc.value.ca:
                self.errors.append(f"Сертификат не должен быть CA, но CA=TRUE")
        except x509.ExtensionNotFound:
            if is_ca:
                self.errors.append(f"CA сертификат не содержит Basic Constraints")

    def _check_key_usage(self, cert: x509.Certificate, name: str):
        try:
            ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
            if not ku.value.key_cert_sign:
                self.warnings.append(f"{name} CA не имеет keyCertSign")
            if not ku.value.crl_sign:
                self.warnings.append(f"{name} CA не имеет cRLSign")
        except x509.ExtensionNotFound:
            self.warnings.append(f"{name} CA не содержит Key Usage")

    def _check_path_length(self, intermediate: x509.Certificate, root: x509.Certificate):
        try:
            bc = intermediate.extensions.get_extension_for_class(x509.BasicConstraints)
            if bc.value.path_length is not None:
                # path_length ограничивает количество подчиненных CA
                if bc.value.path_length < 0:
                    self.warnings.append(f"Path length ограничение {bc.value.path_length} может быть слишком строгим")
        except x509.ExtensionNotFound:
            pass

    def validate_certificate_file(self, cert_path: Path,
                                  ca_cert_path: Path = None,
                                  intermediate_cert_path: Path = None) -> Tuple[bool, List[str], List[str]]:

        with open(cert_path, 'rb') as f:
            cert_data = f.read()
        cert = x509.load_pem_x509_certificate(cert_data)

        if ca_cert_path and intermediate_cert_path:
            with open(ca_cert_path, 'rb') as f:
                root_data = f.read()
            root_cert = x509.load_pem_x509_certificate(root_data)

            with open(intermediate_cert_path, 'rb') as f:
                inter_data = f.read()
            inter_cert = x509.load_pem_x509_certificate(inter_data)

            return self.validate_chain(cert, inter_cert, root_cert)
        else:
            return self._basic_validation(cert)

    def _basic_validation(self, cert: x509.Certificate) -> Tuple[bool, List[str], List[str]]:
        now = datetime.datetime.now(datetime.timezone.utc)
        self._check_validity(cert, "certificate", now)

        try:
            cert.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                cert.signature_hash_algorithm
            )
        except Exception as e:
            self.errors.append(f"Подпись недействительна: {e}")

        return len(self.errors) == 0, self.errors, self.warnings


def validate_full_chain(leaf_path: Path, intermediate_path: Path, root_path: Path) -> bool:

    validator = ChainValidator()
    is_valid, errors, warnings = validator.validate_certificate_file(
        leaf_path, root_path, intermediate_path
    )

    if warnings:
        for w in warnings:
            print(f" {w}")

    if errors:
        for e in errors:
            print(f" {e}")
        return False

    print(" Цепочка сертификатов валидна!")
    return True


if __name__ == '__main__':
    print("Тестирование chain.py")

    from pathlib import Path

    root_cert = Path("./pki/certs/ca.cert.pem")
    inter_cert = Path("./pki/certs/intermediate.cert.pem")
    leaf_cert = Path("./pki/certs/example.com.cert.pem")

    if leaf_cert.exists():
        print("\n--- Проверка цепочки ---")
        validate_full_chain(leaf_cert, inter_cert, root_cert)