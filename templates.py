from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes
from typing import Dict, Any, Optional, List


class CertificateTemplate:
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description

    def get_key_usage(self) -> x509.KeyUsage:

        raise NotImplementedError

    def get_extended_key_usage(self) -> x509.ExtendedKeyUsage:

        raise NotImplementedError

    def get_basic_constraints(self) -> x509.BasicConstraints:

        return x509.BasicConstraints(ca=False, path_length=None)

    def requires_san(self) -> bool:

        return False

    def allowed_san_types(self) -> List[str]:

        return []


class ServerTemplate(CertificateTemplate):

    def __init__(self):
        super().__init__(
            name="server",
            description="Сертификат сервера для TLS/HTTPS"
        )

    def get_key_usage(self) -> x509.KeyUsage:
        return x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        )

    def get_extended_key_usage(self) -> x509.ExtendedKeyUsage:
        return x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.SERVER_AUTH
        ])

    def requires_san(self) -> bool:
        return True

    def allowed_san_types(self) -> List[str]:
        return ['dns', 'ip']


class ClientTemplate(CertificateTemplate):

    def __init__(self):
        super().__init__(
            name="client",
            description="Клиентский сертификат для аутентификации"
        )

    def get_key_usage(self) -> x509.KeyUsage:
        return x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=True,  # Для ECDH
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        )

    def get_extended_key_usage(self) -> x509.ExtendedKeyUsage:
        return x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.CLIENT_AUTH
        ])

    def requires_san(self) -> bool:
        return False

    def allowed_san_types(self) -> List[str]:
        return ['email', 'dns']


class CodeSigningTemplate(CertificateTemplate):

    def __init__(self):
        super().__init__(
            name="code_signing",
            description="Сертификат для подписи кода"
        )

    def get_key_usage(self) -> x509.KeyUsage:
        return x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        )

    def get_extended_key_usage(self) -> x509.ExtendedKeyUsage:
        return x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.CODE_SIGNING
        ])

    def requires_san(self) -> bool:
        return False

    def allowed_san_types(self) -> List[str]:
        return []


# Фабрика шаблонов
class TemplateFactory:

    _templates = {
        'server': ServerTemplate,
        'client': ClientTemplate,
        'code_signing': CodeSigningTemplate,
    }

    @classmethod
    def get_template(cls, template_name: str) -> CertificateTemplate:

        template_name = template_name.lower()
        if template_name not in cls._templates:
            raise ValueError(
                f"Неизвестный шаблон: {template_name}. "
                f"Доступные: {', '.join(cls._templates.keys())}"
            )
        return cls._templates[template_name]()

    @classmethod
    def list_templates(cls) -> list:
        return list(cls._templates.keys())


def apply_template_to_builder(
        builder: x509.CertificateBuilder,
        template: CertificateTemplate,
        san_extension: x509.SubjectAlternativeName = None
) -> x509.CertificateBuilder:

    builder = builder.add_extension(
        template.get_basic_constraints(),
        critical=True
    )

    builder = builder.add_extension(
        template.get_key_usage(),
        critical=True
    )

    builder = builder.add_extension(
        template.get_extended_key_usage(),
        critical=False
    )

    if san_extension:
        builder = builder.add_extension(
            san_extension,
            critical=False
        )

    return builder


if __name__ == '__main__':
    print("Тестирование templates.py")

    print(f"\nДоступные шаблоны: {TemplateFactory.list_templates()}")

    for template_name in TemplateFactory.list_templates():
        print(f"\n--- Шаблон: {template_name} ---")
        template = TemplateFactory.get_template(template_name)
        print(f"Описание: {template.description}")
        print(f"Требуется SAN: {template.requires_san()}")
        print(f"Разрешенные SAN типы: {template.allowed_san_types()}")

        key_usage = template.get_key_usage()
        print(f"Key Usage: digital_signature={key_usage.digital_signature}, "
              f"key_encipherment={key_usage.key_encipherment}, "
              f"key_agreement={key_usage.key_agreement}")

        eku = template.get_extended_key_usage()
        print(f"Extended Key Usage: {[oid._name for oid in eku]}")

    print("\n Все шаблоны созданы успешно!")