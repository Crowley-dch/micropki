from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timezone
from typing import List, Optional, Tuple, Dict, Any
from dataclasses import dataclass, field
from enum import Enum


class ValidationStatus(Enum):
    PASS = "pass"
    FAIL = "fail"
    WARNING = "warning"


@dataclass
class ValidationStep:
    name: str
    status: ValidationStatus
    message: str = ""
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ValidationResult:
    overall_status: ValidationStatus
    steps: List[ValidationStep]
    chain: List[x509.Certificate]
    error_message: str = ""


class PathValidator:
    """Проверка цепочки сертификатов согласно RFC 5280"""

    def __init__(self, validation_time: Optional[datetime] = None):
        self.validation_time = validation_time or datetime.now(timezone.utc)
        self.steps = []

    def build_chain(self, leaf: x509.Certificate,
                    intermediates: List[x509.Certificate],
                    trusted: List[x509.Certificate]) -> List[x509.Certificate]:
        """Строит цепочку от leaf до trusted root"""
        chain = [leaf]
        current = leaf

        while True:
            issuer_found = False
            for cert in intermediates:
                if current.issuer == cert.subject:
                    chain.append(cert)
                    current = cert
                    issuer_found = True
                    break

            if not issuer_found:
                break

        # Проверяем, является ли последний trusted
        last = chain[-1]
        for trust in trusted:
            if last.issuer == trust.subject or last.subject == trust.subject:
                chain.append(trust)
                break

        return chain

    def verify_signature(self, cert: x509.Certificate, issuer: x509.Certificate) -> bool:
        """Проверяет подпись сертификата"""
        try:
            issuer.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm
            )
            return True
        except Exception:
            return False

    def check_validity_period(self, cert: x509.Certificate) -> bool:
        """Проверяет срок действия"""
        return cert.not_valid_before_utc <= self.validation_time <= cert.not_valid_after_utc

    def check_basic_constraints(self, cert: x509.Certificate, is_ca_expected: bool) -> Tuple[bool, str]:
        """Проверяет Basic Constraints"""
        try:
            bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
            if is_ca_expected and not bc.value.ca:
                return False, "Expected CA certificate but CA=FALSE"
            if not is_ca_expected and bc.value.ca:
                return False, "Expected end-entity certificate but CA=TRUE"
            return True, ""
        except x509.ExtensionNotFound:
            if is_ca_expected:
                return False, "CA certificate missing Basic Constraints"
            return True, ""

    def check_key_usage(self, cert: x509.Certificate, required_usage: str) -> Tuple[bool, str]:
        """Проверяет Key Usage"""
        try:
            ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
            if required_usage == 'keyCertSign' and not ku.value.key_cert_sign:
                return False, "Missing keyCertSign in Key Usage"
            if required_usage == 'digitalSignature' and not ku.value.digital_signature:
                return False, "Missing digitalSignature in Key Usage"
            return True, ""
        except x509.ExtensionNotFound:
            return True, ""  # Optional extension

    def check_path_length(self, cert: x509.Certificate, ca_count: int) -> Tuple[bool, str]:
        """Проверяет pathLenConstraint"""
        try:
            bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
            if bc.value.path_length is not None and ca_count > bc.value.path_length:
                return False, f"Path length constraint exceeded: {ca_count} > {bc.value.path_length}"
            return True, ""
        except x509.ExtensionNotFound:
            return True, ""

    def validate_chain(self, leaf: x509.Certificate,
                       intermediates: List[x509.Certificate],
                       trusted: List[x509.Certificate],
                       check_revocation: bool = False) -> ValidationResult:
        """Полная проверка цепочки"""
        steps = []

        # Шаг 1: Построение цепочки
        step = ValidationStep(name="Chain building", status=ValidationStatus.PASS)
        chain = self.build_chain(leaf, intermediates, trusted)
        if len(chain) < 2:
            step.status = ValidationStatus.FAIL
            step.message = "Could not build complete chain to trusted root"
            steps.append(step)
            return ValidationResult(ValidationStatus.FAIL, steps, chain, step.message)
        step.message = f"Chain built with {len(chain)} certificates"
        steps.append(step)

        # Шаг 2-4: Проверка каждого сертификата в цепочке
        for i, cert in enumerate(chain[:-1]):  # Все кроме корневого
            issuer = chain[i + 1]
            is_ca = i < len(chain) - 2  # Последний перед корнем - тоже CA

            # Подпись
            step = ValidationStep(name=f"Signature verification [{i}]", status=ValidationStatus.PASS)
            if not self.verify_signature(cert, issuer):
                step.status = ValidationStatus.FAIL
                step.message = "Invalid signature"
                steps.append(step)
                return ValidationResult(ValidationStatus.FAIL, steps, chain, step.message)
            step.message = "Valid signature"
            steps.append(step)

            # Срок действия
            step = ValidationStep(name=f"Validity period [{i}]", status=ValidationStatus.PASS)
            if not self.check_validity_period(cert):
                step.status = ValidationStatus.FAIL
                step.message = f"Certificate expired or not yet valid"
                steps.append(step)
                return ValidationResult(ValidationStatus.FAIL, steps, chain, step.message)
            step.message = f"Valid from {cert.not_valid_before_utc} to {cert.not_valid_after_utc}"
            steps.append(step)

            # Basic Constraints
            step = ValidationStep(name=f"Basic Constraints [{i}]", status=ValidationStatus.PASS)
            ok, msg = self.check_basic_constraints(cert, is_ca)
            if not ok:
                step.status = ValidationStatus.FAIL
                step.message = msg
                steps.append(step)
                return ValidationResult(ValidationStatus.FAIL, steps, chain, step.message)
            step.message = msg or "OK"
            steps.append(step)

            # Key Usage для CA
            if is_ca:
                step = ValidationStep(name=f"Key Usage (CA) [{i}]", status=ValidationStatus.PASS)
                ok, msg = self.check_key_usage(cert, 'keyCertSign')
                if not ok:
                    step.status = ValidationStatus.FAIL
                    step.message = msg
                    steps.append(step)
                    return ValidationResult(ValidationStatus.FAIL, steps, chain, step.message)
                step.message = msg or "keyCertSign present"
                steps.append(step)

        return ValidationResult(ValidationStatus.PASS, steps, chain, "")


def validate_certificate_chain(leaf_path: str,
                               intermediates_paths: List[str],
                               trusted_paths: List[str],
                               validation_time: Optional[datetime] = None) -> ValidationResult:
    with open(leaf_path, 'rb') as f:
        leaf = x509.load_pem_x509_certificate(f.read())

    intermediates = []
    for path in intermediates_paths:
        with open(path, 'rb') as f:
            intermediates.append(x509.load_pem_x509_certificate(f.read()))

    trusted = []
    for path in trusted_paths:
        with open(path, 'rb') as f:
            trusted.append(x509.load_pem_x509_certificate(f.read()))

    validator = PathValidator(validation_time)
    return validator.validate_chain(leaf, intermediates, trusted)