# modules/registry.py
"""
Registry module — поиск и удаление следов USB-устройства в кустах реестра Windows.

Платформа: Linux Live CD — только кросс-платформенные инструменты.

Покрываемые кусты и ключи:
  SYSTEM (CurrentControlSet):
    - HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\\<VID_PID&...>\\<Serial>
    - HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USB\\<VID_PID>\\<Serial>
    - HKLM\\SYSTEM\\MountedDevices                  → бинарные значения с серийником
    - HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceClasses (GUID-ветки)

  SOFTWARE:
    - HKLM\\SOFTWARE\\Microsoft\\Windows Portable Devices\\Devices
    - HKLM\\SOFTWARE\\Microsoft\\Windows Search\\VolumeInfoCache

  NTUSER.DAT (каждого пользователя):
    - HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2
    - HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs
    - HKCU\\Software\\Microsoft\\Windows\\Shell\\BagMRU  (Shellbags)
    - HKCU\\Software\\Microsoft\\Windows\\Shell\\Bags

Стратегия зачистки:
  - python-registry читает кусты в режиме read-only → получаем offset каждого
    NK/VK-блока, содержащего серийник
  - Открываем файл куста напрямую (mmap) и затираем Value Data нулями
  - Сами NK-ключи (имя ключа = серийник) затираем через нулёвку Name-поля
    в NK-блоке + корректируем Name Length = 0
  - Транзакционные логи (.LOG1 / .LOG2) зачищаем аналогично или удаляем

Зависимости:
  pip install python-registry   # pure Python, кросс-платформенный
                                 # github.com/williballenthin/python-registry
"""

from __future__ import annotations

import mmap
import os
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    from Registry import Registry          # python-registry
    from Registry import RegistryParse    # низкоуровневый доступ к блокам
except ImportError as e:
    raise ImportError(
        "python-registry не установлен.\n"
        "  pip install python-registry"
    ) from e


# ---------------------------------------------------------------------------
# Константы EVTX-структур реестра
# ---------------------------------------------------------------------------

HIVE_MAGIC          = b"regf"
HBIN_MAGIC          = b"hbin"
NK_MAGIC            = b"nk"
VK_MAGIC            = b"vk"

REGF_HEADER_SIZE    = 0x1000          # 4096 байт — первичный заголовок куста
HBIN_HEADER_SIZE    = 0x20            # 32 байта — заголовок hbin-блока
NK_NAME_OFFSET      = 0x4C            # offset имени ключа внутри NK-блока
VK_DATA_OFFSET_OFF  = 0x08           # offset поля DataOffset внутри VK-блока
VK_DATA_LEN_OFF     = 0x04           # offset поля DataLength
VK_NAME_LEN_OFF     = 0x10           # offset длины имени значения
VK_NAME_OFF         = 0x14           # offset самого имени значения

# Флаг: данные хранятся inline (DataLength | 0x80000000)
VK_INLINE_FLAG      = 0x80000000


# ---------------------------------------------------------------------------
# Структуры данных
# ---------------------------------------------------------------------------

@dataclass
class RegistryHit:
    """Одно найденное упоминание серийника в кусте реестра."""
    hive_path:   Path
    key_path:    str                   # полный путь к ключу
    value_name:  Optional[str]        # None → серийник в имени NK-ключа
    block_type:  str                  # "NK" | "VK"
    file_offset: int                  # абсолютный offset в файле куста
    data_offset: int                  # offset начала обнуляемых данных
    data_length: int                  # длина обнуляемого региона
    zeroed:      bool = False


@dataclass
class HiveResult:
    """Результат обработки одного куста."""
    hive_path:   Path
    hits:        list[RegistryHit] = field(default_factory=list)
    errors:      list[str]         = field(default_factory=list)
    skipped:     bool = False


# ---------------------------------------------------------------------------
# Вспомогательные функции
# ---------------------------------------------------------------------------

def _serial_variants(serial: str) -> list[bytes]:
    """
    Возвращает список байтовых паттернов для поиска:
      - серийник как ASCII
      - серийник как UTF-16LE
      - серийник в верхнем и нижнем регистре
    """
    variants = set()
    for s in (serial, serial.upper(), serial.lower()):
        variants.add(s.encode("ascii", errors="replace"))
        variants.add(s.encode("utf-16-le"))
    return list(variants)


def _open_hive(hive_path: Path) -> Optional[Registry.Registry]:
    """Открывает куст через python-registry. Возвращает None при ошибке."""
    try:
        return Registry.Registry(str(hive_path))
    except Exception:
        return None


def _iter_all_keys(root_key):
    """Рекурсивный обход всех ключей куста (BFS)."""
    stack = [root_key]
    while stack:
        key = stack.pop()
        yield key
        try:
            stack.extend(key.subkeys())
        except Exception:
            pass


def _raw_offset_of_key(hive_data: bytes, key_name_bytes: bytes) -> list[int]:
    """
    Ищет NK-блок с именем == key_name_bytes в сыром дампе куста.
    Возвращает список файловых offset'ов найденных NK-блоков.
    """
    offsets = []
    pos = REGF_HEADER_SIZE
    while pos < len(hive_data) - 4:
        idx = hive_data.find(NK_MAGIC, pos)
        if idx == -1:
            break
        # NK-блок: magic(2) + flags(2) + timestamp(8) + ... + name_len(2) + name
        name_len = struct.unpack_from("<H", hive_data, idx + 0x48)[0]
        name_start = idx + NK_NAME_OFFSET
        name_end   = name_start + name_len
        if name_end <= len(hive_data):
            name_bytes = hive_data[name_start:name_end]
            if name_bytes == key_name_bytes:
                offsets.append(idx)
        pos = idx + 2
    return offsets


# ---------------------------------------------------------------------------
# Основной сканер
# ---------------------------------------------------------------------------

class RegistryScanner:
    """
    Сканирует кусты реестра на предмет серийника USB.
    Использует python-registry для высокоуровневого обхода,
    mmap для низкоуровневого zeroing.
    """

    # Пути к кустам относительно корня смонтированного раздела Windows
    HIVE_RELATIVE_PATHS: dict[str, list[str]] = {
        "SYSTEM": [
            "Windows/System32/config/SYSTEM",
        ],
        "SOFTWARE": [
            "Windows/System32/config/SOFTWARE",
        ],
        "NTUSER": [
            # glob-паттерн — expand_user_hives() раскрывает их
            "Users/*/NTUSER.DAT",
        ],
    }

    # Ключи, где имя подключа == серийник (NK-зачистка)
    SERIAL_AS_KEYNAME: list[str] = [
        "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR",
        "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Enum\\USB",
        "HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Enum\\USBSTOR",
        "HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Enum\\USB",
        "HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet002\\Enum\\USBSTOR",
        "HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet002\\Enum\\USB",
    ]

    # Ключи, где серийник может быть в имени/данных значений (VK-зачистка)
    SERIAL_IN_VALUES: list[str] = [
        "HKEY_LOCAL_MACHINE\\SYSTEM\\MountedDevices",
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Portable Devices\\Devices",
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Search\\VolumeInfoCache",
        "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2",
        "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs",
        "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
        "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\Shell\\Bags",
    ]

    def __init__(
        self,
        mount_point: Path,
        serial: str,
        dry_run: bool = True,
        verbose: bool = False,
    ):
        self.mount_point = Path(mount_point)
        self.serial      = serial
        self.dry_run     = dry_run
        self.verbose     = verbose
        self.patterns    = _serial_variants(serial)

    # ------------------------------------------------------------------
    # Публичный интерфейс
    # ------------------------------------------------------------------

    def run(self) -> list[HiveResult]:
        """Запускает полное сканирование и (если не dry_run) zeroing."""
        results: list[HiveResult] = []

        for hive_path in self._collect_hive_paths():
            result = self._process_hive(hive_path)
            results.append(result)

        return results

    # ------------------------------------------------------------------
    # Сбор путей к кустам
    # ------------------------------------------------------------------

    def _collect_hive_paths(self) -> list[Path]:
        paths: list[Path] = []

        # Стандартные кусты
        for hive_type, rel_list in self.HIVE_RELATIVE_PATHS.items():
            for rel in rel_list:
                if "*" in rel:
                    # glob — для NTUSER.DAT нескольких пользователей
                    found = list(self.mount_point.glob(rel))
                    # case-insensitive обход на NTFS через glob
                    if not found:
                        found = list(self.mount_point.glob(rel.lower()))
                    paths.extend(found)
                else:
                    p = self.mount_point / rel
                    if not p.exists():
                        # Пробуем lower-case (NTFS смонтирован case-insensitive)
                        p = self.mount_point / rel.lower()
                    if p.exists():
                        paths.append(p)

        return paths

    # ------------------------------------------------------------------
    # Обработка одного куста
    # ------------------------------------------------------------------

    def _process_hive(self, hive_path: Path) -> HiveResult:
        result = HiveResult(hive_path=hive_path)

        if self.verbose:
            print(f"[registry] Обрабатываем: {hive_path}")

        hive = _open_hive(hive_path)
        if hive is None:
            result.errors.append(f"Не удалось открыть куст: {hive_path}")
            result.skipped = True
            return result

        # 1. Высокоуровневый обход — собираем hits
        try:
            self._scan_all_keys(hive, hive_path, result)
        except Exception as e:
            result.errors.append(f"Ошибка при сканировании: {e}")

        # 2. Бинарный поиск по сырому файлу — ловим всё что пропустил парсер
        try:
            self._scan_raw_binary(hive_path, result)
        except Exception as e:
            result.errors.append(f"Ошибка при бинарном сканировании: {e}")

        # 3. Zeroing найденных hits
        if not self.dry_run and result.hits:
            self._zero_hits(result)

        # 4. Зачищаем транзакционные логи
        if not self.dry_run:
            self._clean_transaction_logs(hive_path, result)

        return result

    # ------------------------------------------------------------------
    # Высокоуровневый обход через python-registry
    # ------------------------------------------------------------------

    def _scan_all_keys(
        self,
        hive: Registry.Registry,
        hive_path: Path,
        result: HiveResult,
    ) -> None:
        root = hive.root()

        for key in _iter_all_keys(root):
            key_path = key.path()

            # --- Проверяем имя самого ключа ---
            if self._matches(key.name().encode("utf-16-le")) or \
               self._matches(key.name().encode("ascii", errors="replace")):
                # NK-hit: серийник в имени ключа
                hit = RegistryHit(
                    hive_path   = hive_path,
                    key_path    = key_path,
                    value_name  = None,
                    block_type  = "NK",
                    file_offset = 0,    # уточним при zeroing через _raw_offset_of_key
                    data_offset = 0,
                    data_length = 0,
                )
                result.hits.append(hit)
                if self.verbose:
                    print(f"  [NK-hit] {key_path}")

            # --- Проверяем значения (VK) ---
            try:
                values = key.values()
            except Exception:
                values = []

            for val in values:
                hit = self._check_value(val, key_path, hive_path)
                if hit:
                    result.hits.append(hit)
                    if self.verbose:
                        print(f"  [VK-hit] {key_path} → {val.name()}")

    def _check_value(
        self,
        val,
        key_path: str,
        hive_path: Path,
    ) -> Optional[RegistryHit]:
        """Проверяет одно значение реестра на наличие серийника."""
        # Проверяем имя значения
        name_match = (
            self._matches(val.name().encode("utf-16-le")) or
            self._matches(val.name().encode("ascii", errors="replace"))
        )

        # Проверяем данные значения (строки и бинарные)
        data_match = False
        try:
            raw = val.raw_data()
            if isinstance(raw, (bytes, bytearray)):
                data_match = self._matches(raw)
        except Exception:
            pass

        if not (name_match or data_match):
            return None

        return RegistryHit(
            hive_path   = hive_path,
            key_path    = key_path,
            value_name  = val.name(),
            block_type  = "VK",
            file_offset = 0,   # уточним при zeroing
            data_offset = 0,
            data_length = 0,
        )

    # ------------------------------------------------------------------
    # Бинарный поиск по сырому файлу куста
    # ------------------------------------------------------------------

    def _scan_raw_binary(self, hive_path: Path, result: HiveResult) -> None:
        """
        Ищет все вхождения серийника (ASCII + UTF-16LE) в сыром файле куста.
        Добавляет hits с точными file_offset / data_offset / data_length.
        """
        try:
            raw = hive_path.read_bytes()
        except OSError as e:
            result.errors.append(f"Не удалось прочитать {hive_path}: {e}")
            return

        seen_offsets: set[int] = set()

        for pattern in self.patterns:
            pos = 0
            while True:
                idx = raw.find(pattern, pos)
                if idx == -1:
                    break
                if idx not in seen_offsets:
                    seen_offsets.add(idx)
                    hit = RegistryHit(
                        hive_path   = hive_path,
                        key_path    = f"<raw@0x{idx:08X}>",
                        value_name  = "<binary-scan>",
                        block_type  = "RAW",
                        file_offset = idx,
                        data_offset = idx,
                        data_length = len(pattern),
                    )
                    # Добавляем только если этот offset не уже покрыт
                    if not any(h.file_offset == idx for h in result.hits):
                        result.hits.append(hit)
                pos = idx + 1

    # ------------------------------------------------------------------
    # Zeroing
    # ------------------------------------------------------------------

    def _zero_hits(self, result: HiveResult) -> None:
        """
        Открывает файл куста и затирает данные для каждого hit.
        RAW-hits: затираем data_offset..data_offset+data_length нулями.
        NK/VK-hits: ищем точный offset через бинарный поиск по имени,
                    затираем Name-поле и/или Data-поле.
        """
        hive_path = result.hive_path

        try:
            raw = bytearray(hive_path.read_bytes())
        except OSError as e:
            result.errors.append(f"Не удалось прочитать для zeroing: {e}")
            return

        modified = False

        for hit in result.hits:
            if hit.zeroed:
                continue

            if hit.block_type == "RAW":
                # Прямое затирание по offset
                end = hit.data_offset + hit.data_length
                if end <= len(raw):
                    raw[hit.data_offset:end] = b"\x00" * hit.data_length
                    hit.zeroed = True
                    modified = True

            elif hit.block_type in ("NK", "VK"):
                # Ищем все вхождения серийника и затираем
                for pattern in self.patterns:
                    pos = 0
                    while True:
                        idx = raw.find(pattern, pos)
                        if idx == -1:
                            break
                        raw[idx: idx + len(pattern)] = b"\x00" * len(pattern)
                        hit.zeroed = True
                        modified = True
                        pos = idx + 1

        if modified:
            try:
                # Пишем атомарно: сначала во временный файл
                tmp_path = hive_path.with_suffix(".tmp_zero")
                tmp_path.write_bytes(raw)
                os.replace(tmp_path, hive_path)
                if self.verbose:
                    print(f"  [zeroed] {hive_path}")
            except OSError as e:
                result.errors.append(f"Не удалось записать zeroed куст: {e}")

    # ------------------------------------------------------------------
    # Транзакционные логи
    # ------------------------------------------------------------------

    def _clean_transaction_logs(
        self, hive_path: Path, result: HiveResult
    ) -> None:
        """
        Зачищает .LOG / .LOG1 / .LOG2 файлы рядом с кустом.
        Стратегия: если лог содержит серийник — затираем аналогично hive.
        """
        for suffix in (".LOG", ".LOG1", ".LOG2",
                       ".log", ".log1", ".log2"):
            log_path = hive_path.with_suffix(suffix)
            if not log_path.exists():
                # Проверяем вариант без смены расширения (SYSTEM.LOG1)
                log_path = Path(str(hive_path) + suffix)

            if not log_path.exists():
                continue

            try:
                log_data = bytearray(log_path.read_bytes())
            except OSError:
                continue

            modified = False
            for pattern in self.patterns:
                pos = 0
                while True:
                    idx = log_data.find(pattern, pos)
                    if idx == -1:
                        break
                    log_data[idx: idx + len(pattern)] = b"\x00" * len(pattern)
                    modified = True
                    pos = idx + 1

            if modified:
                try:
                    tmp = log_path.with_suffix(".tmp_zero")
                    tmp.write_bytes(log_data)
                    os.replace(tmp, log_path)
                    if self.verbose:
                        print(f"  [log-zeroed] {log_path}")
                except OSError as e:
                    result.errors.append(
                        f"Не удалось зачистить лог {log_path}: {e}"
                    )

    # ------------------------------------------------------------------
    # Утилита
    # ------------------------------------------------------------------

    def _matches(self, data: bytes) -> bool:
        """Возвращает True если любой из паттернов найден в data."""
        return any(p in data for p in self.patterns)


# ---------------------------------------------------------------------------
# Функция-точка входа для main.py
# ---------------------------------------------------------------------------

def clean_registry(
    mount_point: Path,
    serial: str,
    dry_run: bool = True,
    verbose: bool = False,
) -> list[HiveResult]:
    """
    Публичный API модуля.

    Args:
        mount_point : путь к смонтированному Windows-разделу (/mnt/windows)
        serial      : серийник USB-устройства (например, "1234ABCD&0")
        dry_run     : True → только сканирование, False → zeroing
        verbose     : подробный вывод в stdout

    Returns:
        Список HiveResult для каждого обработанного куста.
    """
    scanner = RegistryScanner(
        mount_point=mount_point,
        serial=serial,
        dry_run=dry_run,
        verbose=verbose,
    )
    return scanner.run()
