import pytest
from micropki.serial import SerialGenerator, generate_serial_number


class TestSerialGenerator:

    def test_generate_unique(self):
        gen = SerialGenerator()
        serials = set()

        for _ in range(100):
            serial = gen.generate(check_unique=False)
            serials.add(serial)

        assert len(serials) == 100

    def test_serial_positive(self):
        gen = SerialGenerator()
        serial = gen.generate(check_unique=False)
        assert serial > 0

    def test_to_hex(self):
        serial = 0x2A7F
        hex_str = SerialGenerator.to_hex(serial)
        assert hex_str == "2A7F"

    def test_from_hex(self):
        hex_str = "2A7F"
        serial = SerialGenerator.from_hex(hex_str)
        assert serial == 0x2A7F

    def test_roundtrip(self):
        original = 0x123456789ABCDEF
        hex_str = SerialGenerator.to_hex(original)
        result = SerialGenerator.from_hex(hex_str)
        assert original == result

    def test_serial_not_too_big(self):
        gen = SerialGenerator()
        max_serial = (1 << 159) - 1

        for _ in range(50):
            serial = gen.generate(check_unique=False)
            assert serial <= max_serial

    def test_consecutive_generation(self):
        gen = SerialGenerator()
        prev = None
        for _ in range(10):
            current = gen.generate(check_unique=False)
            if prev is not None:
                assert current != prev
            prev = current