import os
import time
from typing import Optional
import threading


class SerialGenerator:
    def __init__(self, db_connection=None):
        self.db_conn = db_connection
        self._lock = threading.Lock()
        self._last_timestamp = 0
        self._counter = 0

    def generate(self, check_unique: bool = True) -> int:
        with self._lock:
            timestamp = int(time.time())

            if timestamp == self._last_timestamp:
                self._counter += 1
                if self._counter >= (1 << 32):
                    time.sleep(1)
                    timestamp = int(time.time())
                    self._counter = 0
            else:
                self._last_timestamp = timestamp
                self._counter = 0

            if self._counter > 0:
                serial = (timestamp << 32) | self._counter
            else:
                random_part = int.from_bytes(os.urandom(4), 'big')
                serial = (timestamp << 32) | random_part

            max_serial = (1 << 159) - 1
            if serial > max_serial:
                serial = serial >> 1

            if check_unique and self.db_conn:
                if not self._is_unique_in_db(serial):
                    # Рекурсивно генерируем новый
                    return self.generate(check_unique)

            return serial

    def _is_unique_in_db(self, serial: int) -> bool:

        if not self.db_conn:
            return True

        try:
            cursor = self.db_conn.cursor()
            serial_hex = hex(serial).upper().replace('X', 'x')
            cursor.execute(
                "SELECT 1 FROM certificates WHERE serial_hex = ?",
                (serial_hex,)
            )
            return cursor.fetchone() is None
        except Exception:
            return True

    @staticmethod
    def to_hex(serial: int) -> str:
        return hex(serial)[2:].upper()

    @staticmethod
    def from_hex(serial_hex: str) -> int:
        return int(serial_hex, 16)


_default_generator = None


def get_serial_generator(db_conn=None) -> SerialGenerator:
    global _default_generator
    if _default_generator is None or db_conn is not None:
        _default_generator = SerialGenerator(db_conn)
    return _default_generator


def generate_serial_number(db_conn=None, check_unique: bool = True) -> int:

    generator = get_serial_generator(db_conn)
    return generator.generate(check_unique)


if __name__ == '__main__':
    print("Тестирование serial.py")

    gen = SerialGenerator()
    serials = set()
    for i in range(100):
        serial = gen.generate(check_unique=False)
        serials.add(serial)
        print(f"  {i + 1}: {hex(serial)}")

    print(f"\nУникальных серийных номеров: {len(serials)} из 100")
    assert len(serials) == 100, "Обнаружены дубликаты!"
    print(" Тест 1 пройден: 100 уникальных номеров")

    serial = gen.generate()
    print(f"\nПример серийного номера: {hex(serial)}")
    print(f"  hex без 0x: {SerialGenerator.to_hex(serial)}")
    print(f"  обратно: {hex(SerialGenerator.from_hex(SerialGenerator.to_hex(serial)))}")

    print("\n Все тесты пройдены!")