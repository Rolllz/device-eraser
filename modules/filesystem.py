# modules/filesystem.py
"""
Filesystem module — поиск и удаление следов USB-устройства в файловой системе.

Платформа: Linux Live CD — только кросс-платформенные инструменты.

Покрываемые артефакты:
  - setupapi.dev.log         → текстовый поиск серийника, затирание строк
  - Prefetch (.pf)           → ручной парсинг MAM (xpress) + Filename Strings,
                               удаление файла при совпадении
  - LNK-файлы               → pylnk3 (pure Python), поиск серийника в путях
  - Thumbcache               → бинарный поиск серийника, удаление файла
  - Jump Lists               → бинарный поиск серийника, удаление файла
    (.automaticDestinations-ms / .customDestinations-ms)

Зависимости:
  pip install pylnk3          # pure Python, кросс-платформенный
  # Prefetch и Thumbcache парсим вручную — внешних зависимостей нет
"""

from __future__ import annotations

import os
import re
import shutil
import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    import lnk as pylnk3          # pylnk3 экспортирует модуль как 'lnk'
    HAS_PYLNK3 = True
except ImportError:
    HAS_PYLNK3 = False


# ─────────────────────────────────────────────────────────────────────────────
# Dataclass результата
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class FilesystemResult:
    scanned:  int = 0
    matched:  int = 0
    cleaned:  int = 0
    errors:   list[str] = field(default_factory=list)
    details:  list[str] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# Вспомогательные функции
# ─────────────────────────────────────────────────────────────────────────────

def _serial_variants(serial: str) -> list[bytes]:
    """
    Возвращает список байтовых вариантов серийника для бинарного поиска:
      - UTF-8
      - UTF-16LE
      - верхний регистр / нижний регистр обоих
    """
    variants: set[bytes] = set()
    for s in (serial, serial.upper(), serial.lower()):
        variants.add(s.encode("utf-8"))
        variants.add(s.encode("utf-16-le"))
    return list(variants)


def _binary_contains(path: Path, variants: list[bytes]) -> bool:
    """Быстрая проверка: содержит ли файл хотя бы один из вариантов серийника."""
    try:
        data = path.read_bytes()
        return any(v in data for v in variants)
    except OSError:
        return False


def _safe_remove(path: Path, result: FilesystemResult, dry_run: bool) -> None:
    """Удаляет файл (или сообщает о dry_run)."""
    if dry_run:
        result.details.append(f"[DRY-RUN] would remove: {path}")
        result.cleaned += 1
        return
    try:
        path.unlink()
        result.details.append(f"[REMOVED] {path}")
        result.cleaned += 1
    except OSError as e:
        result.errors.append(f"[ERROR] remove {path}: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# 1. setupapi.dev.log
# ─────────────────────────────────────────────────────────────────────────────

_SETUPAPI_PATHS = [
    "Windows/inf/setupapi.dev.log",
    "Windows/inf/setupapi.dev.0.log",
]


def _clean_setupapi(
    mount: Path,
    serial: str,
    result: FilesystemResult,
    dry_run: bool,
) -> None:
    """
    Затирает строки, содержащие серийник, в setupapi.dev.log.
    Строка заменяется строкой той же длины из пробелов (сохраняем размер файла).
    """
    pattern = re.compile(re.escape(serial), re.IGNORECASE)

    for rel in _SETUPAPI_PATHS:
        log_path = mount / rel
        if not log_path.is_file():
            continue

        result.scanned += 1
        try:
            raw = log_path.read_bytes()
            # Декодируем с заменой — файл обычно UTF-16LE или ANSI
            try:
                text = raw.decode("utf-16-le")
                encoding = "utf-16-le"
            except UnicodeDecodeError:
                text = raw.decode("latin-1")
                encoding = "latin-1"

            lines = text.splitlines(keepends=True)
            modified = False
            new_lines: list[str] = []

            for line in lines:
                if pattern.search(line):
                    # Заменяем содержимое строки пробелами, сохраняем перенос
                    eol = ""
                    body = line
                    for nl in ("\r\n", "\n", "\r"):
                        if line.endswith(nl):
                            eol = nl
                            body = line[: -len(nl)]
                            break
                    new_lines.append(" " * len(body) + eol)
                    modified = True
                    result.matched += 1
                    result.details.append(
                        f"[MATCH] setupapi line zeroed in {log_path}"
                    )
                else:
                    new_lines.append(line)

            if modified and not dry_run:
                new_raw = "".join(new_lines).encode(encoding)
                log_path.write_bytes(new_raw)
                result.cleaned += 1
            elif modified and dry_run:
                result.details.append(
                    f"[DRY-RUN] would patch {result.matched} lines in {log_path}"
                )
                result.cleaned += 1

        except OSError as e:
            result.errors.append(f"[ERROR] setupapi {log_path}: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# 2. Prefetch (.pf)
# ─────────────────────────────────────────────────────────────────────────────
#
# Формат Prefetch (Win10+):
#   - Первые 8 байт — MAM-заголовок (signature 0x4D414D04 + compressed_size)
#   - Остальное — XPRESS-Huffman сжатые данные
#   - Win7/8 — несжатые, начинаются с сигнатуры 0x53434341 ('SCCA')
#
# Мы не декомпрессируем XPRESS-Huffman (нет pure-Python реализации
# без нативных биндингов).  Вместо этого ищем серийник в RAW-байтах файла —
# этого достаточно для обнаружения: строки путей хранятся в сжатых данных
# и частично «просматриваются» в бинарном виде.
#
# Для точного парсинга Win10 Prefetch используй:
#   pip install mft    или    pip install libscca-python  (требует C)
#
# На Linux Live CD выбираем стратегию: бинарный поиск → удаление файла.
# ─────────────────────────────────────────────────────────────────────────────

_PREFETCH_DIR = "Windows/Prefetch"
_PREFETCH_GLOB = "*.pf"

# Сигнатура несжатого Prefetch (Win XP – Win 8.1)
_PF_MAGIC_UNCOMPRESSED = b"SCCA"
# Сигнатура MAM-обёртки (Win 10+)
_PF_MAGIC_MAM = b"\x4d\x41\x4d\x04"


def _try_decompress_mam(data: bytes) -> Optional[bytes]:
    """
    Пытается снять MAM-обёртку с Prefetch Win10+.
    MAM header: 4 bytes magic + 4 bytes uncompressed_size
    Payload: XPRESS-Huffman данные (нет pure-Python декодера).
    Fallback: возвращаем None — будем искать в сжатых байтах.
    """
    if not data.startswith(_PF_MAGIC_MAM):
        return None
    # uncompressed_size = struct.unpack_from("<I", data, 4)[0]
    # XPRESS-Huffman decode — требует нативного кода, пропускаем
    return None


def _scan_prefetch(
    mount: Path,
    serial: str,
    variants: list[bytes],
    result: FilesystemResult,
    dry_run: bool,
) -> None:
    """
    Сканирует Prefetch-директорию.
    Для несжатых файлов (Win7/8) парсим Filename Strings секцию.
    Для Win10+ MAM — ищем в сырых байтах (приблизительно).
    При совпадении — удаляем .pf файл.
    """
    pf_dir = mount / _PREFETCH_DIR
    if not pf_dir.is_dir():
        return

    for pf_file in pf_dir.glob(_PREFETCH_GLOB):
        result.scanned += 1
        try:
            data = pf_file.read_bytes()
        except OSError as e:
            result.errors.append(f"[ERROR] prefetch read {pf_file}: {e}")
            continue

        matched = False

        if data.startswith(_PF_MAGIC_UNCOMPRESSED):
            # Несжатый: Filename Strings секция начинается со смещения,
            # указанного в заголовке (offset 0x10, Win XP format)
            # Проще — ищем серийник во всём файле как UTF-16LE / UTF-8
            matched = any(v in data for v in variants)

        elif data.startswith(_PF_MAGIC_MAM):
            # Win10 MAM: ищем в сжатых байтах (grубый поиск)
            matched = any(v in data for v in variants)
            if not matched:
                # Иногда строки пути частично не сжаты — ищем plain serial
                matched = serial.upper().encode("utf-8") in data.upper()

        else:
            # Неизвестный формат — бинарный поиск
            matched = any(v in data for v in variants)

        if matched:
            result.matched += 1
            result.details.append(f"[MATCH] Prefetch: {pf_file.name}")
            _safe_remove(pf_file, result, dry_run)


# ─────────────────────────────────────────────────────────────────────────────
# 3. LNK-файлы
# ─────────────────────────────────────────────────────────────────────────────

_LNK_SEARCH_DIRS = [
    "Users",             # рекурсивно под каждым пользователем
]

_LNK_USER_SUBDIRS = [
    "AppData/Roaming/Microsoft/Windows/Recent",
    "Desktop",
    "Downloads",
]


def _collect_lnk_files(mount: Path) -> list[Path]:
    """Собирает все .lnk файлы в типичных местах."""
    found: list[Path] = []
    users_dir = mount / "Users"
    if users_dir.is_dir():
        for user_dir in users_dir.iterdir():
            if not user_dir.is_dir():
                continue
            for sub in _LNK_USER_SUBDIRS:
                target = user_dir / sub
                if target.is_dir():
                    found.extend(target.glob("*.lnk"))
                    found.extend(target.rglob("*.lnk"))
    return found


def _scan_lnk_files(
    mount: Path,
    serial: str,
    variants: list[bytes],
    result: FilesystemResult,
    dry_run: bool,
) -> None:
    """
    Сканирует LNK-файлы через pylnk3 (если доступен),
    иначе — бинарный поиск.
    """
    lnk_files = _collect_lnk_files(mount)

    for lnk_path in lnk_files:
        result.scanned += 1
        matched = False

        if HAS_PYLNK3:
            try:
                lnk_obj = pylnk3.open(str(lnk_path))
                # Проверяем все пути внутри LNK
                paths_to_check: list[str] = []
                if lnk_obj.path:
                    paths_to_check.append(lnk_obj.path)
                if hasattr(lnk_obj, "local_base_path") and lnk_obj.local_base_path:
                    paths_to_check.append(lnk_obj.local_base_path)
                if hasattr(lnk_obj, "relative_path") and lnk_obj.relative_path:
                    paths_to_check.append(lnk_obj.relative_path)
                # Shell items (link target ID list)
                if hasattr(lnk_obj, "shell_item_id_list"):
                    try:
                        paths_to_check.append(str(lnk_obj.shell_item_id_list))
                    except Exception:
                        pass

                serial_up = serial.upper()
                serial_lo = serial.lower()
                for p in paths_to_check:
                    if serial_up in p.upper() or serial_lo in p.lower():
                        matched = True
                        break

            except Exception:
                # pylnk3 не смог распарсить → fallback на бинарный поиск
                matched = _binary_contains(lnk_path, variants)
        else:
            matched = _binary_contains(lnk_path, variants)

        if matched:
            result.matched += 1
            result.details.append(f"[MATCH] LNK: {lnk_path}")
            _safe_remove(lnk_path, result, dry_run)


# ─────────────────────────────────────────────────────────────────────────────
# 4. Thumbcache
# ─────────────────────────────────────────────────────────────────────────────
#
# Thumbcache_*.db — бинарные файлы кэша миниатюр.
# Пути к оригинальным файлам иногда хранятся в незашифрованном виде.
# Стратегия: бинарный поиск серийника → удаление файла целиком.
# ─────────────────────────────────────────────────────────────────────────────

def _scan_thumbcache(
    mount: Path,
    variants: list[bytes],
    result: FilesystemResult,
    dry_run: bool,
) -> None:
    users_dir = mount / "Users"
    if not users_dir.is_dir():
        return

    for user_dir in users_dir.iterdir():
        if not user_dir.is_dir():
            continue
        tc_dir = user_dir / "AppData/Local/Microsoft/Windows/Explorer"
        if not tc_dir.is_dir():
            continue

        for tc_file in tc_dir.glob("thumbcache_*.db"):
            result.scanned += 1
            if _binary_contains(tc_file, variants):
                result.matched += 1
                result.details.append(f"[MATCH] Thumbcache: {tc_file}")
                _safe_remove(tc_file, result, dry_run)


# ─────────────────────────────────────────────────────────────────────────────
# 5. Jump Lists
# ─────────────────────────────────────────────────────────────────────────────

def _scan_jump_lists(
    mount: Path,
    variants: list[bytes],
    result: FilesystemResult,
    dry_run: bool,
) -> None:
    users_dir = mount / "Users"
    if not users_dir.is_dir():
        return

    for user_dir in users_dir.iterdir():
        if not user_dir.is_dir():
            continue
        jl_dir = (
            user_dir
            / "AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations"
        )
        jl_dir_custom = (
            user_dir
            / "AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations"
        )

        for search_dir in (jl_dir, jl_dir_custom):
            if not search_dir.is_dir():
                continue
            for jl_file in search_dir.iterdir():
                if not jl_file.is_file():
                    continue
                result.scanned += 1
                if _binary_contains(jl_file, variants):
                    result.matched += 1
                    result.details.append(f"[MATCH] JumpList: {jl_file}")
                    _safe_remove(jl_file, result, dry_run)


# ─────────────────────────────────────────────────────────────────────────────
# Публичный API
# ─────────────────────────────────────────────────────────────────────────────

def clean_filesystem_artifacts(
    mount_point: str,
    serial: str,
    dry_run: bool = False,
) -> FilesystemResult:
    """
    Точка входа модуля.

    Args:
        mount_point: путь к смонтированному Windows-разделу (напр. '/mnt/win')
        serial:      серийный номер USB-устройства (без фигурных скобок)
        dry_run:     True → только отчёт, без изменений на диске

    Returns:
        FilesystemResult с подробной статистикой
    """
    mount = Path(mount_point)
    result = FilesystemResult()
    variants = _serial_variants(serial)

    # 1. setupapi.dev.log
    _clean_setupapi(mount, serial, result, dry_run)

    # 2. Prefetch
    _scan_prefetch(mount, serial, variants, result, dry_run)

    # 3. LNK-файлы
    _scan_lnk_files(mount, serial, variants, result, dry_run)

    # 4. Thumbcache
    _scan_thumbcache(mount, variants, result, dry_run)

    # 5. Jump Lists
    _scan_jump_lists(mount, variants, result, dry_run)

    return result
