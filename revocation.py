from enum import IntEnum
from typing import Optional
from datetime import datetime


class RevocationReason(IntEnum):
    UNSPECIFIED = 0
    KEY_COMPROMISE = 1
    CA_COMPROMISE = 2
    AFFILIATION_CHANGED = 3
    SUPERSEDED = 4
    CESSATION_OF_OPERATION = 5
    CERTIFICATE_HOLD = 6
    REMOVE_FROM_CRL = 8
    PRIVILEGE_WITHDRAWN = 9
    AA_COMPROMISE = 10


REASON_MAP = {
    'unspecified': RevocationReason.UNSPECIFIED,
    'keycompromise': RevocationReason.KEY_COMPROMISE,
    'cacompromise': RevocationReason.CA_COMPROMISE,
    'affiliationchanged': RevocationReason.AFFILIATION_CHANGED,
    'superseded': RevocationReason.SUPERSEDED,
    'cessationofoperation': RevocationReason.CESSATION_OF_OPERATION,
    'certificatehold': RevocationReason.CERTIFICATE_HOLD,
    'removefromcrl': RevocationReason.REMOVE_FROM_CRL,
    'privilegewithdrawn': RevocationReason.PRIVILEGE_WITHDRAWN,
    'aacompromise': RevocationReason.AA_COMPROMISE,
}


def get_reason_code(reason_str: str) -> int:
    normalized = reason_str.lower().replace('_', '').replace('-', '')

    if normalized not in REASON_MAP:
        valid = ', '.join([r for r in REASON_MAP.keys()])
        raise ValueError(f"Неподдерживаемая причина отзыва: {reason_str}. "
                         f"Доступные: {valid}")

    return REASON_MAP[normalized]


def get_reason_string(code: int) -> str:
    for name, reason in REASON_MAP.items():
        if reason.value == code:
            return name
    return 'unspecified'


def revoke_certificate(db, serial_hex: str, reason_str: str, force: bool = False) -> bool:

    from datetime import datetime

    serial_hex = serial_hex.upper().lstrip('0X')

    cert = db.get_certificate_by_serial(serial_hex)
    if not cert:
        raise ValueError(f"Сертификат с серийным номером {serial_hex} не найден")

    if cert['status'] == 'revoked':
        if not force:
            raise ValueError(f"Сертификат уже отозван. Используйте --force для принудительного обновления")
        else:
            reason_code = get_reason_code(reason_str)
            reason_string = get_reason_string(reason_code)
            db.update_status(serial_hex, 'revoked', reason_string)
            return True

    reason_code = get_reason_code(reason_str)
    reason_string = get_reason_string(reason_code)

    success = db.update_status(serial_hex, 'revoked', reason_string)
    return success


def get_revoked_certificates_for_ca(db, ca_cert) -> list:

    issuer_dn = str(ca_cert.subject)

    all_revoked = db.list_certificates(status='revoked')

    return [c for c in all_revoked if c['issuer'] == issuer_dn]


if __name__ == '__main__':
    print("Тестирование revocation.py")

    test_reasons = [
        'keyCompromise', 'cACompromise', 'superseded',
        'affiliationChanged', 'certificateHold'
    ]

    for reason in test_reasons:
        code = get_reason_code(reason)
        back = get_reason_string(code)
        print(f"  {reason} -> {code} -> {back}")

    print("\n Тесты пройдены!")