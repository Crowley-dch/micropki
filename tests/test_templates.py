import pytest
from micropki.templates import TemplateFactory, ServerTemplate, ClientTemplate, CodeSigningTemplate


class TestTemplates:

    def test_get_server_template(self):
        template = TemplateFactory.get_template("server")
        assert isinstance(template, ServerTemplate)
        assert template.name == "server"
        assert template.requires_san() is True
        assert template.allowed_san_types() == ['dns', 'ip']

    def test_get_client_template(self):
        template = TemplateFactory.get_template("client")
        assert isinstance(template, ClientTemplate)
        assert template.name == "client"
        assert template.requires_san() is False

    def test_get_code_signing_template(self):
        template = TemplateFactory.get_template("code_signing")
        assert isinstance(template, CodeSigningTemplate)
        assert template.name == "code_signing"
        assert template.allowed_san_types() == []

    def test_invalid_template(self):
        with pytest.raises(ValueError, match="Неизвестный шаблон"):
            TemplateFactory.get_template("invalid")

    def test_list_templates(self):
        templates = TemplateFactory.list_templates()
        assert 'server' in templates
        assert 'client' in templates
        assert 'code_signing' in templates