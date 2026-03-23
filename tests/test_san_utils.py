import pytest
from micropki.san_utils import (
    parse_san_string,
    parse_san_list,
    create_san_extension,
    validate_san_for_template,
    SANType
)

class TestSANUtils:

    def test_parse_dns(self):
        san_type, value = parse_san_string("dns:example.com")
        assert san_type == SANType.DNS
        assert value == "example.com"

    def test_parse_ip(self):
        san_type, value = parse_san_string("ip:192.168.1.1")
        assert san_type == SANType.IP
        assert value == "192.168.1.1"

    def test_parse_email(self):
        san_type, value = parse_san_string("email:admin@example.com")
        assert san_type == SANType.EMAIL
        assert value == "admin@example.com"

    def test_parse_invalid_format(self):
        with pytest.raises(ValueError):
            parse_san_string("invalid")

    def test_parse_list(self):
        san_list = ["dns:example.com", "ip:192.168.1.1"]
        result = parse_san_list(san_list)
        assert result[SANType.DNS] == ["example.com"]
        assert result[SANType.IP] == ["192.168.1.1"]

    def test_validate_server_san_valid(self):
        san_dict = {SANType.DNS: ["example.com"]}
        assert validate_san_for_template(san_dict, "server") is True

    def test_validate_server_san_invalid(self):
        san_dict = {}  # Пустой SAN
        with pytest.raises(ValueError, match="хотя бы один DNS или IP SAN"):
            validate_san_for_template(san_dict, "server")

    def test_validate_code_signing_san_invalid(self):
        san_dict = {SANType.DNS: ["example.com"]}
        with pytest.raises(ValueError, match="не должен содержать SAN"):
            validate_san_for_template(san_dict, "code_signing")