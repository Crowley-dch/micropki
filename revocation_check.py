
from cryptography import x509
from cryptography.x509.ocsp import OCSPRequestBuilder, OCSPResponseStatus
from cryptography.hazmat.primitives import hashes, serialization, padding
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timezone
from typing import Optional, Tuple, Dict, Any
from dataclasses import dataclass
from enum import Enum
import requests
import logging

class RevocationStatus(Enum):
    GOOD = "good"
    REVOKED = "revoked"
    UNKNOWN = "unknown"
    ERROR = "error"


@dataclass
class RevocationResult:
    status: RevocationStatus
    method: str  # 'ocsp', 'crl', 'fallback', 'none'
    revocation_date: Optional[str] = None
    revocation_reason: Optional[str] = None
    message: str = ""


class RevocationChecker:
    """Проверка статуса сертификата через CRL и OCSP с fallback"""

    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger('micropki.revocation')

    def _log(self, level: str, message: str):
        if self.logger:
            getattr(self.logger, level)(message)

    def extract_ocsp_url(self, cert: x509.Certificate) -> Optional[str]:
        """Извлекает OCSP URL из AIA расширения"""
        try:
            aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
            for desc in aia.value:
                if desc.access_method == x509.oid.AuthorityInformationAccessOID.OCSP:
                    return desc.access_location.value
        except x509.ExtensionNotFound:
            pass
        return None

    def extract_crl_url(self, cert: x509.Certificate) -> Optional[str]:
        """Извлекает CRL URL из CDP расширения"""
        try:
            cdp = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)
            for point in cdp.value:
                for name in point.full_name:
                    if isinstance(name, x509.UniformResourceIdentifier):
                        return name.value
        except x509.ExtensionNotFound:
            pass
        return None

    def check_ocsp(self, cert: x509.Certificate, issuer: x509.Certificate,
                   ocsp_url: Optional[str] = None) -> RevocationResult:
        """Проверяет статус через OCSP"""
        if ocsp_url is None:
            ocsp_url = self.extract_ocsp_url(cert)

        if not ocsp_url:
            return RevocationResult(
                status=RevocationStatus.ERROR,
                method='ocsp',
                message="No OCSP URL found in certificate"
            )

        try:
            builder = OCSPRequestBuilder()
            builder = builder.add_certificate(cert, issuer, hashes.SHA256())
            request = builder.build()
            request_der = request.public_bytes(serialization.Encoding.DER)

            response = requests.post(
                ocsp_url,
                data=request_der,
                headers={'Content-Type': 'application/ocsp-request'},
                timeout=10
            )

            if response.status_code != 200:
                return RevocationResult(
                    status=RevocationStatus.ERROR,
                    method='ocsp',
                    message=f"HTTP {response.status_code}"
                )

            ocsp_response = x509.ocsp.load_der_ocsp_response(response.content)

            if ocsp_response.response_status != OCSPResponseStatus.SUCCESSFUL:
                return RevocationResult(
                    status=RevocationStatus.ERROR,
                    method='ocsp',
                    message=f"OCSP response status: {ocsp_response.response_status}"
                )

            for single in ocsp_response.certificate_status:
                if single.cert_status == x509.ocsp.OCSPCertStatus.GOOD:
                    return RevocationResult(
                        status=RevocationStatus.GOOD,
                        method='ocsp',
                        message="Certificate is good"
                    )
                elif single.cert_status == x509.ocsp.OCSPCertStatus.REVOKED:
                    return RevocationResult(
                        status=RevocationStatus.REVOKED,
                        method='ocsp',
                        revocation_date=single.revocation_time.isoformat(),
                        revocation_reason=str(single.revocation_reason) if single.revocation_reason else None,
                        message="Certificate is revoked"
                    )
                else:
                    return RevocationResult(
                        status=RevocationStatus.UNKNOWN,
                        method='ocsp',
                        message="Certificate status unknown"
                    )

        except Exception as e:
            return RevocationResult(
                status=RevocationStatus.ERROR,
                method='ocsp',
                message=str(e)
            )

        return RevocationResult(
            status=RevocationStatus.UNKNOWN,
            method='ocsp',
            message="No response"
        )

    def check_crl(self, cert: x509.Certificate, issuer: x509.Certificate,
                  crl_data: Optional[bytes] = None, crl_url: Optional[str] = None) -> RevocationResult:
        """Проверяет статус через CRL"""
        if crl_data is None and crl_url is None:
            crl_url = self.extract_crl_url(cert)

        if crl_url:
            try:
                response = requests.get(crl_url, timeout=10)
                if response.status_code == 200:
                    crl_data = response.content
            except Exception as e:
                return RevocationResult(
                    status=RevocationStatus.ERROR,
                    method='crl',
                    message=f"Failed to fetch CRL: {e}"
                )

        if crl_data is None:
            return RevocationResult(
                status=RevocationStatus.ERROR,
                method='crl',
                message="No CRL provided"
            )

        try:
            crl = x509.load_pem_x509_crl(crl_data)
        except:
            crl = x509.load_der_x509_crl(crl_data)

        # Проверяем подпись CRL
        try:
            issuer.public_key().verify(
                crl.signature,
                crl.tbs_certificate_bytes,
                padding.PKCS1v15(),
                crl.signature_hash_algorithm
            )
        except Exception:
            return RevocationResult(
                status=RevocationStatus.ERROR,
                method='crl',
                message="Invalid CRL signature"
            )

        # Проверяем срок действия CRL
        now = datetime.now(timezone.utc)
        if crl.next_update and crl.next_update < now:
            self._log('warning', f"CRL is expired (next update: {crl.next_update})")

        # Ищем серийный номер
        serial_hex = hex(cert.serial_number)[2:].upper().lstrip('0')
        serial_int = int(serial_hex, 16) if serial_hex else cert.serial_number

        for revoked in crl:
            if revoked.serial_number == cert.serial_number:
                reason = None
                try:
                    for ext in revoked.extensions:
                        if ext.oid._name == 'CRLReason':
                            reason = str(ext.value)
                            break
                except:
                    pass

                return RevocationResult(
                    status=RevocationStatus.REVOKED,
                    method='crl',
                    revocation_date=revoked.revocation_date.isoformat(),
                    revocation_reason=reason,
                    message="Certificate found in CRL"
                )

        return RevocationResult(
            status=RevocationStatus.GOOD,
            method='crl',
            message="Certificate not found in CRL"
        )

    def check_status(self, cert: x509.Certificate, issuer: x509.Certificate,
                     ocsp_url: Optional[str] = None,
                     crl_data: Optional[bytes] = None,
                     crl_url: Optional[str] = None,
                     prefer_ocsp: bool = True) -> RevocationResult:
        """
        Проверяет статус сертификата с fallback логикой

        Приоритет: OCSP -> CRL -> unknown
        """
        if prefer_ocsp:
            ocsp_result = self.check_ocsp(cert, issuer, ocsp_url)

            if ocsp_result.status == RevocationStatus.GOOD:
                return ocsp_result
            elif ocsp_result.status == RevocationStatus.REVOKED:
                return ocsp_result
            elif ocsp_result.status == RevocationStatus.ERROR:
                self._log('warning', f"OCSP failed: {ocsp_result.message}, falling back to CRL")

            # Fallback to CRL
            crl_result = self.check_crl(cert, issuer, crl_data, crl_url)
            if crl_result.status != RevocationStatus.ERROR:
                crl_result.method = 'fallback'
                return crl_result
        else:
            crl_result = self.check_crl(cert, issuer, crl_data, crl_url)
            if crl_result.status != RevocationStatus.ERROR:
                return crl_result

            ocsp_result = self.check_ocsp(cert, issuer, ocsp_url)
            if ocsp_result.status != RevocationStatus.ERROR:
                return ocsp_result

        return RevocationResult(
            status=RevocationStatus.UNKNOWN,
            method='none',
            message="All revocation checks failed"
        )


def check_certificate_status(cert_path: str, issuer_path: str,
                             ocsp_url: Optional[str] = None,
                             crl_path: Optional[str] = None,
                             crl_url: Optional[str] = None) -> RevocationResult:
    """Удобная функция для проверки статуса из файлов"""
    with open(cert_path, 'rb') as f:
        cert = x509.load_pem_x509_certificate(f.read())

    with open(issuer_path, 'rb') as f:
        issuer = x509.load_pem_x509_certificate(f.read())

    crl_data = None
    if crl_path:
        with open(crl_path, 'rb') as f:
            crl_data = f.read()

    checker = RevocationChecker()
    return checker.check_status(cert, issuer, ocsp_url, crl_data, crl_url)