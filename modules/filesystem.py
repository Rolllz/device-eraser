# modules/filesystem.py
"""
Filesystem module — поиск и удаление следов USB-устройства в файловой системе.

Покрываемые артефакты:
  - setupapi.dev.log       → текстовый поиск серийника, затирание строк
  - Prefetch (.pf)         → MAM-декомпрессия, парсинг Filename Strings,
                             удаление файла при совпадении
  - LNK-файлы             → pylnk3, поиск серийника в путях / shell items
  - Thumbcache             → бинарный поиск серийника, удаление файла
  - Jump Lists (.automaticDestinations-ms / .customDestinations-ms)
                           → бинарный поиск, удаление файла

Зависимости:
  pip install pylnk3 windowsprefetch
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes
import os
import re
import shutil
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ── опциональные зависимости ──────────────────────────────────────────────────
try:
    import lnk  # pylnk3
    LNK_AVAILABLE = True
except ImportError:
    LNK_AVAILABLE = False

try:
    import prefetch as pflib  # windowsprefetch
    PREFETCH_LIB_AVAILABLE = True
except ImportError:
    PREFETCH_LIB_AVAILABLE = False


# ─────────────────────────────────────────────────────────────────────────────
#  Типы данных
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class FSHit:
    """Одна находка в файловой системе."""
    artifact: str          # "prefetch" | "setupapi" | "lnk" | "thumbcache" | "jumplist"
    path: Path
    reason: str            # краткое описание совпадения
    action_taken: str = "" # "deleted" | "zeroed" | "skipped"


@dataclass
class FSResult:
    hits: list[FSHit] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def merge(self, other: "FSResult") -> None:
        self.hits.extend(other.hits)
        self.errors.extend(other.errors)


# ─────────────────────────────────────────────────────────────────────────────
#  MAM-декомпрессия (Windows 10+ Prefetch)
# ─────────────────────────────────────────────────────────────────────────────

_COMPRESSION_FORMAT_XPRESS_HUFF = 4
_STATUS_SUCCESS = 0

def _decompress_mam(data: bytes) -> Optional[bytes]:
    """
    Распаковывает MAM-сжатый prefetch-файл через ntdll.
    Формат заголовка MAM:
      bytes 0-3 : сигнатура  'MAM\x04'
      bytes 4-7 : uint32 LE — размер распакованных данных
      bytes 8+  : сжатый payload
    Возвращает распакованные байты или None при ошибке.
    """
    if data[:3] != b"MAM":
        return data  # уже не сжат (Win XP/7/8)

    uncompressed_size = struct.unpack_from("<I", data, 4)[0]
    compressed_payload = data[8:]

    ntdll = ctypes.CDLL("ntdll.dll")

    # --- получаем размер рабочего буфера ---
    compress_ws_size   = ctypes.c_ulong(0)
    compress_frag_size = ctypes.c_ulong(0)
    status = ntdll.RtlGetCompressionWorkSpaceSize(
        ctypes.c_ushort(_COMPRESSION_FORMAT_XPRESS_HUFF),
        ctypes.byref(compress_ws_size),
        ctypes.byref(compress_frag_size),
    )
    if status != _STATUS_SUCCESS:
        return None

    # --- рабочий буфер ---
    workspace = (ctypes.c_byte * compress_ws_size.value)()

    # --- буфер вывода ---
    out_buf  = (ctypes.c_byte * uncompressed_size)()
    out_size = ctypes.c_ulong(0)

    in_buf = (ctypes.c_byte * len(compressed_payload))(*compressed_payload)

    status = ntdll.RtlDecompressBufferEx(
        ctypes.c_ushort(_COMPRESSION_FORMAT_XPRESS_HUFF),
        out_buf,
        ctypes.c_ulong(uncompressed_size),
        in_buf,
        ctypes.c_ulong(len(compressed_payload)),
        ctypes.byref(out_size),
        workspace,
    )
    if status != _STATUS_SUCCESS:
        return None

    return bytes(out_buf[: out_size.value])


# ─────────────────────────────────────────────────────────────────────────────
#  Парсинг Prefetch — Filename Strings секция (ручной разбор)
# ─────────────────────────────────────────────────────────────────────────────

def _parse_pf_filenames(raw: bytes) -> list[str]:
    """
    Извлекает список путей из секции Filename Strings prefetch-файла.
    Поддерживает форматы v17 (XP), v23 (Win7), v26 (Win8), v30 (Win10).

    Структура заголовка (версия 30 — Win10, offset в байтах):
      0x00 : uint32 — сигнатура SCCA ('SCCA')
      0x04 : uint32 — версия формата
      ...
      0x54 : uint32 — offset секции Filename Strings
      0x58 : uint32 — длина секции Filename Strings (в байтах)
    """
    if len(raw) < 0x60:
        return []

    sig = raw[4:8]  # версия: 17, 23, 26, 30
    version = struct.unpack_from("<I", raw, 4)[0]

    # Смещения различаются по версии
    offset_map = {
        17: (0x54, 0x58),
        23: (0x54, 0x58),
        26: (0x54, 0x58),
        30: (0x54, 0x58),
    }
    if version not in offset_map:
        return []

    off_offset, len_offset = offset_map[version]
    fn_offset = struct.unpack_from("<I", raw, off_offset)[0]
    fn_length = struct.unpack_from("<I", raw, len_offset)[0]

    if fn_offset + fn_length > len(raw):
        return []

    blob = raw[fn_offset: fn_offset + fn_length]

    # Имена — null-terminated UTF-16 LE строки
    result = []
    try:
        decoded = blob.decode("utf-16-le", errors="replace")
        for part in decoded.split("\x00"):
            s = part.strip()
            if s:
                result.append(s)
    except Exception:
        pass

    return result


# ─────────────────────────────────────────────────────────────────────────────
#  Prefetch
# ─────────────────────────────────────────────────────────────────────────────

_PREFETCH_DIR = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "Prefetch"


def _scan_prefetch(serial: str, backup_dir: Optional[Path], dry_run: bool) -> FSResult:
    """
    Сканирует все .pf файлы.
    Если серийник найден в Filename Strings → удаляет файл (с бэкапом).
    """
    result = FSResult()
    serial_upper = serial.upper()

    if not _PREFETCH_DIR.exists():
        return result

    for pf_path in _PREFETCH_DIR.glob("*.pf"):
        try:
            raw = pf_path.read_bytes()
        except PermissionError as e:
            result.errors.append(f"[prefetch] Нет доступа: {pf_path} — {e}")
            continue

        decompressed = _decompress_mam(raw)
        if decompressed is None:
            result.errors.append(f"[prefetch] Не удалось распаковать: {pf_path}")
            continue

        filenames = _parse_pf_filenames(decompressed)
        matched = [f for f in filenames if serial_upper in f.upper()]

        if not matched:
            continue

        hit = FSHit(
            artifact="prefetch",
            path=pf_path,
            reason=f"Серийник найден в {len(matched)} путях: {matched[:3]}{'...' if len(matched) > 3 else ''}",
        )

        if dry_run:
            hit.action_taken = "dry_run"
        else:
            if backup_dir:
                _backup_file(pf_path, backup_dir, "prefetch")
            try:
                pf_path.unlink()
                hit.action_taken = "deleted"
            except Exception as e:
                hit.action_taken = "error"
                result.errors.append(f"[prefetch] Ошибка удаления {pf_path}: {e}")

        result.hits.append(hit)

    return result


# ─────────────────────────────────────────────────────────────────────────────
#  setupapi.dev.log
# ─────────────────────────────────────────────────────────────────────────────

_SETUPAPI_PATHS = [
    Path(os.environ.get("SystemRoot", r"C:\Windows")) / "INF" / "setupapi.dev.log",
    Path(os.environ.get("SystemRoot", r"C:\Windows")) / "INF" / "setupapi.app.log",
    Path(os.environ.get("SystemRoot", r"C:\Windows")) / "setupapi.log",  # XP
]

_LINE_ZERO = " " * 80  # чем затираем строку (пробелы, длина ≥ макс. строки)


def _scan_setupapi(serial: str, backup_dir: Optional[Path], dry_run: bool) -> FSResult:
    """
    Ищет серийник в setupapi.dev.log.
    Стратегия: перезаписывает совпадающие строки пробелами (zeroing),
    сохраняя смещения файла неизменными.
    """
    result = FSResult()
    serial_upper = serial.upper()

    for log_path in _SETUPAPI_PATHS:
        if not log_path.exists():
            continue

        try:
            content = log_path.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            result.errors.append(f"[setupapi] Чтение {log_path}: {e}")
            continue

        lines = content.splitlines(keepends=True)
        hit_indices = [i for i, ln in enumerate(lines) if serial_upper in ln.upper()]

        if not hit_indices:
            continue

        hit = FSHit(
            artifact="setupapi",
            path=log_path,
            reason=f"Серийник в строках: {[i+1 for i in hit_indices[:10]]}",
        )

        if dry_run:
            hit.action_taken = "dry_run"
        else:
            if backup_dir:
                _backup_file(log_path, backup_dir, "setupapi")

            # Затираем только совпадающие строки
            for i in hit_indices:
                ending = "\r\n" if lines[i].endswith("\r\n") else "\n"
                lines[i] = (" " * (len(lines[i].rstrip("\r\n")))) + ending

            try:
                log_path.write_text("".join(lines), encoding="utf-8")
                hit.action_taken = "zeroed"
            except Exception as e:
                hit.action_taken = "error"
                result.errors.append(f"[setupapi] Запись {log_path}: {e}")

        result.hits.append(hit)

    return result


# ─────────────────────────────────────────────────────────────────────────────
#  LNK-файлы
# ─────────────────────────────────────────────────────────────────────────────

_LNK_SEARCH_DIRS = [
    Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Recent",
    Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Office" / "Recent",
    Path(os.environ.get("USERPROFILE", "")) / "Desktop",
]


def _scan_lnk(serial: str, backup_dir: Optional[Path], dry_run: bool) -> FSResult:
    """
    Ищет серийник в .lnk-файлах через pylnk3.
    При совпадении — удаляет файл.
    Если pylnk3 недоступен — бинарный поиск как fallback.
    """
    result = FSResult()
    serial_upper = serial.upper()
    serial_bytes = serial_upper.encode("utf-16-le")

    for search_dir in _LNK_SEARCH_DIRS:
        if not search_dir.exists():
            continue

        for lnk_path in search_dir.rglob("*.lnk"):
            found = False
            reason = ""

            if LNK_AVAILABLE:
                try:
                    lnk_file = lnk.parse(str(lnk_path))
                    # Проверяем target path и working dir
                    for attr in ("path", "work_dir", "arguments"):
                        val = getattr(lnk_file, attr, None)
                        if val and serial_upper in str(val).upper():
                            found = True
                            reason = f"Серийник в поле '{attr}': {val}"
                            break
                except Exception:
                    pass  # fallback ниже

            if not found:
                # Бинарный fallback
                try:
                    raw = lnk_path.read_bytes()
                    if serial_bytes in raw or serial_upper.encode("ascii") in raw:
                        found = True
                        reason = "Серийник найден (бинарный поиск)"
                except Exception as e:
                    result.errors.append(f"[lnk] Чтение {lnk_path}: {e}")
                    continue

            if not found:
                continue

            hit = FSHit(artifact="lnk", path=lnk_path, reason=reason)

            if dry_run:
                hit.action_taken = "dry_run"
            else:
                if backup_dir:
                    _backup_file(lnk_path, backup_dir, "lnk")
                try:
                    lnk_path.unlink()
                    hit.action_taken = "deleted"
                except Exception as e:
                    hit.action_taken = "error"
                    result.errors.append(f"[lnk] Удаление {lnk_path}: {e}")

            result.hits.append(hit)

    return result


# ─────────────────────────────────────────────────────────────────────────────
#  Thumbcache
# ─────────────────────────────────────────────────────────────────────────────

_THUMBCACHE_DIR = (
    Path(os.environ.get("LOCALAPPDATA", ""))
    / "Microsoft" / "Windows" / "Explorer"
)


def _scan_thumbcache(serial: str, backup_dir: Optional[Path], dry_run: bool) -> FSResult:
    """
    Бинарный поиск серийника в файлах thumbcache_*.db и iconcache_*.db.
    При совпадении — удаляет файл.
    """
    result = FSResult()
    serial_upper = serial.upper()
    needles = [
        serial_upper.encode("utf-16-le"),
        serial_upper.encode("ascii"),
        serial.lower().encode("utf-16-le"),
    ]

    if not _THUMBCACHE_DIR.exists():
        return result

    patterns = ["thumbcache_*.db", "iconcache_*.db"]
    for pattern in patterns:
        for tc_path in _THUMBCACHE_DIR.glob(pattern):
            try:
                raw = tc_path.read_bytes()
            except Exception as e:
                result.errors.append(f"[thumbcache] Чтение {tc_path}: {e}")
                continue

            found = any(needle in raw for needle in needles)
            if not found:
                continue

            hit = FSHit(
                artifact="thumbcache",
                path=tc_path,
                reason="Серийник найден (бинарный поиск)",
            )

            if dry_run:
                hit.action_taken = "dry_run"
            else:
                if backup_dir:
                    _backup_file(tc_path, backup_dir, "thumbcache")
                try:
                    tc_path.unlink()
                    hit.action_taken = "deleted"
                except Exception as e:
                    hit.action_taken = "error"
                    result.errors.append(f"[thumbcache] Удаление {tc_path}: {e}")

            result.hits.append(hit)

    return result


# ─────────────────────────────────────────────────────────────────────────────
#  Jump Lists
# ─────────────────────────────────────────────────────────────────────────────

_JUMPLIST_DIRS = [
    Path(os.environ.get("APPDATA", ""))
    / "Microsoft" / "Windows" / "Recent" / "AutomaticDestinations",
    Path(os.environ.get("APPDATA", ""))
    / "Microsoft" / "Windows" / "Recent" / "CustomDestinations",
]


def _scan_jumplists(serial: str, backup_dir: Optional[Path], dry_run: bool) -> FSResult:
    """
    Бинарный поиск серийника в файлах Jump Lists.
    При совпадении — удаляет файл.
    """
    result = FSResult()
    serial_upper = serial.upper()
    needles = [
        serial_upper.encode("utf-16-le"),
        serial_upper.encode("ascii"),
    ]

    for jl_dir in _JUMPLIST_DIRS:
        if not jl_dir.exists():
            continue

        for jl_path in jl_dir.iterdir():
            if jl_path.suffix.lower() not in (
                ".automaticDestinations-ms".lower(),
                ".customDestinations-ms".lower(),
            ) and "destinations" not in jl_path.name.lower():
                continue

            try:
                raw = jl_path.read_bytes()
            except Exception as e:
                result.errors.append(f"[jumplist] Чтение {jl_path}: {e}")
                continue

            found = any(needle in raw for needle in needles)
            if not found:
                continue

            hit = FSHit(
                artifact="jumplist",
                path=jl_path,
                reason="Серийник найден (бинарный поиск)",
            )

            if dry_run:
                hit.action_taken = "dry_run"
            else:
                if backup_dir:
                    _backup_file(jl_path, backup_dir, "jumplist")
                try:
                    jl_path.unlink()
                    hit.action_taken = "deleted"
                except Exception as e:
                    hit.action_taken = "error"
                    result.errors.append(f"[jumplist] Удаление {jl_path}: {e}")

            result.hits.append(hit)

    return result


# ─────────────────────────────────────────────────────────────────────────────
#  Вспомогательные функции
# ─────────────────────────────────────────────────────────────────────────────

def _backup_file(src: Path, backup_root: Path, sub: str) -> None:
    """Копирует файл в backup_root / sub / <имя файла>, не перезаписывая."""
    dest_dir = backup_root / sub
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / src.name
    counter = 0
    while dest.exists():
        counter += 1
        dest = dest_dir / f"{src.stem}_{counter}{src.suffix}"
    shutil.copy2(str(src), str(dest))


# ─────────────────────────────────────────────────────────────────────────────
#  Публичный API
# ─────────────────────────────────────────────────────────────────────────────

def scan_and_clean(
    serial: str,
    backup_dir: Optional[Path] = None,
    dry_run: bool = False,
) -> FSResult:
    """
    Точка входа модуля.

    :param serial:     Серийный номер USB-устройства (любой регистр).
    :param backup_dir: Директория для резервных копий. None — без бэкапа.
    :param dry_run:    True — только найти, не изменять файлы.
    :return:           FSResult со всеми находками и ошибками.
    """
    result = FSResult()
    result.merge(_scan_setupapi(serial, backup_dir, dry_run))
    result.merge(_scan_prefetch(serial, backup_dir, dry_run))
    result.merge(_scan_lnk(serial, backup_dir, dry_run))
    result.merge(_scan_thumbcache(serial, backup_dir, dry_run))
    result.merge(_scan_jumplists(serial, backup_dir, dry_run))
    return result
