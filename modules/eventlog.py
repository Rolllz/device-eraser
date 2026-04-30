# modules/eventlog.py
"""
Event Log module — поиск и zeroing записей .evtx, содержащих серийник USB.

Платформа: Linux Live CD — только кросс-платформенные инструменты.

Стратегия zeroing:
  - Парсим .evtx через python-evtx (pure Python, работает на Linux)
  - Получаем byte-offset каждой записи внутри чанка
  - Если XML-представление записи содержит серийник — затираем байты
    Data-payload записи нулями (от record_data_offset до конца записи)
  - Заголовок файла и магические байты чанка НЕ трогаем —
    файл остаётся структурно валидным
  - Контрольную сумму чанка (CRC32) пересчитываем вручную

Покрываемые журналы (пути относительно смонтированного Windows-раздела):
  - System.evtx
  - Security.evtx
  - Microsoft-Windows-DriverFrameworks-UserMode%4Operational.evtx
  - Microsoft-Windows-Kernel-PnP%4Configuration.evtx
  - Microsoft-Windows-WPD-MTPClassDriver%4Operational.evtx

Зависимости:
  pip install python-evtx        # pure Python, кросс-платформенный
"""

from __future__ import annotations

import binascii
import mmap
import os
import shutil
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ── python-evtx ───────────────────────────────────────────────────────────────
try:
    import Evtx.Evtx as evtx_lib
    import Evtx.Views as evtx_views
    EVTX_AVAILABLE = True
except ImportError:
    EVTX_AVAILABLE = False


# ─────────────────────────────────────────────────────────────────────────────
#  КОНСТАНТЫ ФОРМАТА .evtx
# ─────────────────────────────────────────────────────────────────────────────

EVTX_FILE_MAGIC      = b"ElfFile\x00"
EVTX_CHUNK_MAGIC     = b"ElfChnk\x00"
EVTX_RECORD_MAGIC    = b"\x2a\x2a\x00\x00"

# Offsets внутри File Header (512 байт)
FILE_HDR_SIZE         = 512
FILE_HDR_CHUNK_COUNT  = 0x58   # uint64, количество чанков

# Offsets внутри Chunk Header (512 байт)
CHUNK_HDR_SIZE            = 512
CHUNK_HDR_CRC32_HEADER    = 0x7C   # uint32 — CRC32 первых 120 байт заголовка
CHUNK_HDR_CRC32_DATA      = 0x80   # uint32 — CRC32 всего чанка (кроме этого поля)
CHUNK_HDR_LAST_RECORD_OFF = 0x28   # uint64 — offset последней записи в чанке
CHUNK_HDR_FREE_SPACE_OFF  = 0x30   # uint64 — offset начала свободного места

# Размер Record Header
RECORD_HDR_SIZE = 24   # magic(4) + size(4) + record_id(8) + timestamp(8)

# Chunk size по умолчанию — 65536 байт (0x10000)
CHUNK_SIZE = 65536


# ─────────────────────────────────────────────────────────────────────────────
#  Типы данных
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class EventLogHit:
    """Одна найденная запись .evtx, содержащая серийник."""
    log_path:     Path
    chunk_offset: int          # абсолютный offset чанка в файле
    record_offset: int         # абсолютный offset записи в файле
    record_id:    int
    event_id:     int
    xml_snippet:  str          # первые 300 символов XML для отчёта
    zeroed:       bool = False
    error:        Optional[str] = None


@dataclass
class EventLogResult:
    """Итог обработки одного .evtx файла."""
    log_path:  Path
    hits:      list[EventLogHit] = field(default_factory=list)
    skipped:   bool = False
    skip_reason: Optional[str] = None

    @property
    def total_hits(self) -> int:
        return len(self.hits)

    @property
    def total_zeroed(self) -> int:
        return sum(1 for h in self.hits if h.zeroed)


# ─────────────────────────────────────────────────────────────────────────────
#  Вспомогательные функции
# ─────────────────────────────────────────────────────────────────────────────

def _chunk_count(data: bytes) -> int:
    """Читает количество чанков из File Header."""
    if data[:8] != EVTX_FILE_MAGIC:
        raise ValueError("Не валидный .evtx файл (неверная магия заголовка)")
    return struct.unpack_from("<Q", data, FILE_HDR_CHUNK_COUNT)[0]


def _iter_chunk_offsets(data: bytes) -> list[int]:
    """
    Возвращает список абсолютных offset-ов чанков.
    Чанки начинаются строго после 512-байтного File Header и
    следуют непрерывно по 65536 байт каждый.
    """
    offsets: list[int] = []
    pos = FILE_HDR_SIZE
    while pos + CHUNK_HDR_SIZE <= len(data):
        if data[pos:pos + 8] == EVTX_CHUNK_MAGIC:
            offsets.append(pos)
        pos += CHUNK_SIZE
    return offsets


def _recalc_chunk_crc(chunk_data: bytearray) -> None:
    """
    Пересчитывает и записывает оба CRC32 полей чанка на месте.

    Chunk Header CRC32 (offset 0x7C, 4 байта):
      CRC32 от байт [0..120) чанка, поле 0x7C обнуляется при вычислении.

    Chunk Data CRC32 (offset 0x80, 4 байта):
      CRC32 от байт [128..CHUNK_SIZE) чанка.
    """
    # --- Header CRC ---
    tmp = bytearray(chunk_data[:CHUNK_HDR_SIZE])
    struct.pack_into("<I", tmp, CHUNK_HDR_CRC32_HEADER, 0)
    hdr_crc = binascii.crc32(bytes(tmp[:120])) & 0xFFFFFFFF
    struct.pack_into("<I", chunk_data, CHUNK_HDR_CRC32_HEADER, hdr_crc)

    # --- Data CRC ---
    data_crc = binascii.crc32(bytes(chunk_data[128:])) & 0xFFFFFFFF
    struct.pack_into("<I", chunk_data, CHUNK_HDR_CRC32_DATA, data_crc)


def _iter_records_in_chunk(
    data: bytes,
    chunk_abs_offset: int
) -> list[tuple[int, int, int]]:
    """
    Итерирует записи внутри чанка.

    Возвращает список (abs_record_offset, record_size, record_id).
    record_id берём из Record Header (bytes 8..16, uint64 LE).
    """
    results: list[tuple[int, int, int]] = []
    pos = chunk_abs_offset + CHUNK_HDR_SIZE  # записи идут после заголовка чанка
    chunk_end = chunk_abs_offset + CHUNK_SIZE

    while pos + RECORD_HDR_SIZE <= chunk_end:
        magic = data[pos:pos + 4]
        if magic != EVTX_RECORD_MAGIC:
            break  # конец записей в чанке

        record_size = struct.unpack_from("<I", data, pos + 4)[0]
        if record_size < RECORD_HDR_SIZE or pos + record_size > chunk_end:
            break  # повреждённая запись — прекращаем

        record_id = struct.unpack_from("<Q", data, pos + 8)[0]
        results.append((pos, record_size, record_id))
        pos += record_size

    return results


def _extract_event_id_from_xml(xml: str) -> int:
    """Извлекает EventID из XML-строки (простой поиск, без lxml)."""
    import re
    m = re.search(r"<EventID[^>]*>(\d+)</EventID>", xml)
    return int(m.group(1)) if m else -1


# ─────────────────────────────────────────────────────────────────────────────
#  Основной класс
# ─────────────────────────────────────────────────────────────────────────────

class EventLogScanner:
    """
    Сканирует .evtx файлы на наличие серийника USB и
    по запросу зануляет payload найденных записей.

    Параметры
    ----------
    serial : str
        Серийник (или его фрагмент) для поиска, например "1234ABCD".
    windows_root : Path
        Корень смонтированного Windows-раздела, например Path("/mnt/windows").
    dry_run : bool
        Если True — только сканирует, не модифицирует файлы.
    backup : bool
        Если True — создаёт .bak копию перед модификацией.
    extra_logs : list[str]
        Дополнительные пути к .evtx (относительно windows_root или абсолютные).
    """

    # Стандартные журналы (относительно windows_root)
    DEFAULT_LOGS: list[str] = [
        "Windows/System32/winevt/Logs/System.evtx",
        "Windows/System32/winevt/Logs/Security.evtx",
        "Windows/System32/winevt/Logs/"
            "Microsoft-Windows-DriverFrameworks-UserMode%4Operational.evtx",
        "Windows/System32/winevt/Logs/"
            "Microsoft-Windows-Kernel-PnP%4Configuration.evtx",
        "Windows/System32/winevt/Logs/"
            "Microsoft-Windows-WPD-MTPClassDriver%4Operational.evtx",
    ]

    def __init__(
        self,
        serial: str,
        windows_root: Path,
        dry_run: bool = True,
        backup: bool = True,
        extra_logs: Optional[list[str]] = None,
    ) -> None:
        if not EVTX_AVAILABLE:
            raise RuntimeError(
                "python-evtx не установлен. "
                "Выполните: pip install python-evtx"
            )
        self.serial       = serial.strip()
        self.windows_root = windows_root
        self.dry_run      = dry_run
        self.backup       = backup
        self._log_paths   = self._resolve_log_paths(extra_logs or [])
    
  
    # ── разрешение путей ──────────────────────────────────────────────────────

    def _resolve_log_paths(self, extra: list[str]) -> list[Path]:
        paths: list[Path] = []
        for rel in self.DEFAULT_LOGS + extra:
            p = Path(rel)
            if not p.is_absolute():
                p = self.windows_root / p
            paths.append(p)
        return paths

    # ── публичный API ─────────────────────────────────────────────────────────

    def scan(self) -> list[EventLogResult]:
        """
        Сканирует все журналы.
        Возвращает список EventLogResult (по одному на файл).
        """
        results: list[EventLogResult] = []
        for log_path in self._log_paths:
            results.append(self._process_file(log_path, zero=False))
        return results

    def scan_and_zero(self) -> list[EventLogResult]:
        """
        Сканирует журналы и зануляет найденные записи.
        Если dry_run=True — зануление пропускается (только сканирование).
        """
        results: list[EventLogResult] = []
        for log_path in self._log_paths:
            results.append(self._process_file(log_path, zero=True))
        return results

    # ── обработка одного файла ────────────────────────────────────────────────

    def _process_file(self, log_path: Path, zero: bool) -> EventLogResult:
        result = EventLogResult(log_path=log_path)

        if not log_path.exists():
            result.skipped = True
            result.skip_reason = "файл не найден"
            return result

        if not os.access(log_path, os.R_OK):
            result.skipped = True
            result.skip_reason = "нет прав на чтение"
            return result

        # --- Шаг 1: найти совпадения через python-evtx ---
        try:
            hits = self._find_hits(log_path)
        except Exception as exc:
            result.skipped = True
            result.skip_reason = f"ошибка парсинга: {exc}"
            return result

        result.hits = hits

        if not hits or not zero or self.dry_run:
            return result

        # --- Шаг 2: читаем файл целиком в bytearray ---
        if self.backup:
            self._make_backup(log_path)

        try:
            raw = bytearray(log_path.read_bytes())
        except OSError as exc:
            for h in hits:
                h.error = f"чтение файла: {exc}"
            return result

        # --- Шаг 3: зануляем payload каждого хита ---
        affected_chunks: set[int] = set()

        for hit in hits:
            try:
                self._zero_record(raw, hit)
                affected_chunks.add(hit.chunk_offset)
                hit.zeroed = True
            except Exception as exc:
                hit.error = str(exc)

        # --- Шаг 4: пересчитываем CRC затронутых чанков ---
        for chunk_off in affected_chunks:
            chunk_ba = bytearray(raw[chunk_off: chunk_off + CHUNK_SIZE])
            _recalc_chunk_crc(chunk_ba)
            raw[chunk_off: chunk_off + CHUNK_SIZE] = chunk_ba

        # --- Шаг 5: записываем обратно ---
        try:
            log_path.write_bytes(bytes(raw))
        except OSError as exc:
            for h in hits:
                if h.zeroed:
                    h.zeroed = False
                    h.error = f"запись файла: {exc}"

        return result

    # ── поиск совпадений через python-evtx ───────────────────────────────────

    def _find_hits(self, log_path: Path) -> list[EventLogHit]:
        hits: list[EventLogHit] = []
        serial_lower = self.serial.lower()

        with evtx_lib.Evtx(str(log_path)) as log:
            for chunk in log.chunks():
                chunk_offset = chunk.offset()
                for record in chunk.records():
                    try:
                        xml = record.xml()
                    except Exception:
                        continue

                    if serial_lower not in xml.lower():
                        continue

                    hits.append(EventLogHit(
                        log_path      = log_path,
                        chunk_offset  = chunk_offset,
                        record_offset = record.offset(),
                        record_id     = record.record_num(),
                        event_id      = _extract_event_id_from_xml(xml),
                        xml_snippet   = xml[:300],
                    ))

        return hits

    # ── zeroing одной записи ──────────────────────────────────────────────────

    def _zero_record(self, raw: bytearray, hit: EventLogHit) -> None:
        """
        Затирает Data-payload записи нулями.

        Структура Record:
          [0..4)   magic  \x2a\x2a\x00\x00
          [4..8)   size   uint32 — полный размер записи
          [8..16)  record_id uint64
          [16..24) timestamp uint64
          [24..size-4) ← BINARY XML payload  ← зануляем здесь
          [size-4..size) copy of size (uint32)
        """
        rec_off  = hit.record_offset
        rec_size = struct.unpack_from("<I", raw, rec_off + 4)[0]

        payload_start = rec_off + RECORD_HDR_SIZE
        payload_end   = rec_off + rec_size - 4  # -4 для trailing size

        if payload_end <= payload_start:
            raise ValueError(
                f"Некорректный размер записи {rec_size} "
                f"по offset {rec_off:#x}"
            )

        # Зануляем payload (binary XML)
        raw[payload_start:payload_end] = b"\x00" * (payload_end - payload_start)

    # ── backup ────────────────────────────────────────────────────────────────

    @staticmethod
    def _make_backup(log_path: Path) -> None:
        bak = log_path.with_suffix(log_path.suffix + ".bak")
        if not bak.exists():
            shutil.copy2(log_path, bak)


# ─────────────────────────────────────────────────────────────────────────────
#  Отчёт
# ─────────────────────────────────────────────────────────────────────────────

def format_report(results: list[EventLogResult]) -> str:
    """Возвращает текстовый отчёт по результатам сканирования."""
    lines: list[str] = ["=== Event Log Report ===", ""]

    for res in results:
        lines.append(f"[LOG] {res.log_path.name}")

        if res.skipped:
            lines.append(f"  ⚠  Пропущен: {res.skip_reason}")
            lines.append("")
            continue

        if not res.hits:
            lines.append("  ✓  Совпадений не найдено")
            lines.append("")
            continue

        lines.append(f"  Найдено записей : {res.total_hits}")
        lines.append(f"  Занулено        : {res.total_zeroed}")

        for hit in res.hits:
            status = "ZEROED" if hit.zeroed else ("ERROR" if hit.error else "FOUND")
            lines.append(
                f"    [{status}] "
                f"RecordID={hit.record_id}  "
                f"EventID={hit.event_id}  "
                f"chunk@{hit.chunk_offset:#010x}  "
                f"record@{hit.record_offset:#010x}"
            )
            if hit.error:
                lines.append(f"      ✗ {hit.error}")
            lines.append(f"      XML: {hit.xml_snippet[:120].strip()} …")

        lines.append("")

    total_files   = len(results)
    total_skipped = sum(1 for r in results if r.skipped)
    total_hits    = sum(r.total_hits for r in results)
    total_zeroed  = sum(r.total_zeroed for r in results)

    lines += [
        "─" * 40,
        f"Файлов обработано : {total_files - total_skipped}/{total_files}",
        f"Записей найдено   : {total_hits}",
        f"Записей занулено  : {total_zeroed}",
    ]
    return "\n".join(lines)
