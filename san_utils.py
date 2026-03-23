import ipaddress
from typing import List, Tuple, Dict, Any
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.hazmat.backends import default_backend


class SANType:
    DNS = "dns"
    IP = "ip"
    EMAIL = "email"
    URI = "uri"


SAN_TYPE_MAP = {
    SANType.DNS: x509.DNSName,
    SANType.IP: x509.IPAddress,
    SANType.EMAIL: x509.RFC822Name,
    SANType.URI: x509.UniformResourceIdentifier,
}


def parse_san_string(san_str: str) -> Tuple[str, str]:
    if ':' not in san_str:
        raise ValueError(f"Неверный формат SAN: {san_str}. Ожидается 'type:value'")

    san_type, value = san_str.split(':', 1)
    san_type = san_type.lower().strip()
    value = value.strip()

    if san_type not in [SANType.DNS, SANType.IP, SANType.EMAIL, SANType.URI]:
        raise ValueError(f"Неподдерживаемый тип SAN: {san_type}. Доступные: dns, ip, email, uri")

    # Валидация IP адреса
    if san_type == SANType.IP:
        try:
            ipaddress.ip_address(value)
        except ValueError:
            raise ValueError(f"Неверный IP адрес: {value}")

    return san_type, value


def parse_san_list(san_args: List[str]) -> Dict[str, List[str]]:
    result = {SANType.DNS: [], SANType.IP: [], SANType.EMAIL: [], SANType.URI: []}

    for san_str in san_args:
        san_type, value = parse_san_string(san_str)
        result[san_type].append(value)

    return result


def create_san_extension(san_dict: Dict[str, List[str]]) -> x509.SubjectAlternativeName:
    general_names = []

    for dns in san_dict.get(SANType.DNS, []):
        general_names.append(x509.DNSName(dns))

    for ip in san_dict.get(SANType.IP, []):
        general_names.append(x509.IPAddress(ipaddress.ip_address(ip)))

    for email in san_dict.get(SANType.EMAIL, []):
        general_names.append(x509.RFC822Name(email))

    for uri in san_dict.get(SANType.URI, []):
        general_names.append(x509.UniformResourceIdentifier(uri))

    return x509.SubjectAlternativeName(general_names)


def validate_san_for_template(san_dict: Dict[str, List[str]], template_name: str) -> bool:

    if template_name == 'server':
        if not san_dict.get(SANType.DNS) and not san_dict.get(SANType.IP):
            raise ValueError("Сертификат сервера должен содержать хотя бы один DNS или IP SAN")

        if san_dict.get(SANType.EMAIL):
            raise ValueError("Сертификат сервера не должен содержать email SAN")

    elif template_name == 'client':
        if not san_dict.get(SANType.EMAIL) and not san_dict.get(SANType.DNS):
            pass

    elif template_name == 'code_signing':
        if any(san_dict.values()):
            raise ValueError("Сертификат подписи кода не должен содержать SAN")

    return True


if __name__ == '__main__':
    print("Тестирование san_utils.py")

    test_sans = ["dns:example.com", "dns:www.example.com", "ip:192.168.1.1", "email:admin@example.com"]
    parsed = parse_san_list(test_sans)
    print(f"Парсинг SAN: {parsed}")

    san_ext = create_san_extension(parsed)
    print(f"Создано расширение SAN: {san_ext}")

    print("\nТест валидации:")
    server_sans = {"dns": ["example.com"], "ip": []}
    try:
        validate_san_for_template(server_sans, "server")
        print("Server SAN валидны")
    except ValueError as e:
        print(f" Ошибка: {e}")

    try:
        validate_san_for_template(server_sans, "code_signing")
        print("Должна быть ошибка!")
    except ValueError as e:
        print(f"✅ Правильно отклонено: {e}")