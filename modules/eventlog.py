# modules/eventlog.py
"""
Event Log module — поиск и zeroing записей .evtx, содержащих серийник USB.

Стратегия zeroing:
  - Парсим .evtx через python-evtx → получаем byte-offset каждой записи
  - Если XML-представление записи содержит серийник — затираем ТОЛЬКО
    Data-секцию записи (байты после ElfChnk заголовка) нулями
  - Заголовок чанка (chunk header) и магические байты НЕ трогаем —
    файл остаётся валидным, Eventviewer его откроет
  - Контрольные суммы чанка пересчитываем через crc32

Покрываемые журналы (по умолчанию):
  - System.evtx
  - Security.evtx
  - Microsoft-Windows-DriverFrameworks-UserMode%4Operational.evtx
  - Microsoft-Windows-Kernel-PnP%4Configuration.evtx
  - Microsoft-Windows-WPD-MTPClassDriver%4Operational.evtx

Зависимости:
  pip install python-evtx
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
from zlib import crc32

try:
    import Evtx.Evtx as evtx_lib
    import Evtx.Views as evtx_views
    EVTX_AVAILABLE = True
except ImportError:
    EVTX_AVAILABLE = False


# ─────────────────────────────────────────────
#  Константы EVTX-формата
# ─────────────────────────────────────────────

EVTX_FILE_MAGIC   = b"ElfFile\x00"
EVTX_CHUNK_MAGIC  = b"ElfChnk\x00"
EVTX_RECORD_MAGIC = b"\x2a\x2a\x00\x00"   # 0x00002A2A little-endian

EVTX_FILE_HEADER_SIZE  = 4096   # первые 4 КБ — file header + padding
EVTX_CHUNK_SIZE        = 65536  # каждый чанк ровно 64 КБ
EVTX_CHUNK_HEADER_SIZE = 512    # первые 512 байт чанка — chunk header

# Offsets внутри chunk header (все little-endian)
CHUNK_HEADER_OFFSET_FIRST_RECORD   = 8    # uint64 — номер первой записи
CHUNK_HEADER_OFFSET_LAST_RECORD    = 16   # uint64 — номер последней записи
CHUNK_HEADER_OFFSET_LAST_RECORD_ID = 24   # uint64
CHUNK_HEADER_OFFSET_FREE_SPACE     = 120  # uint32 — смещение свободного места
CHUNK_HEADER_OFFSET_RECORDS_CRC    = 124  # uint32 — CRC32 записей
CHUNK_HEADER_OFFSET_HEADER_CRC     = 128  # uint32 — CRC32 самого заголовка (0..127 + 132..511)

RECORD_HEADER_SIZE = 24  # magic(4) + size(4) + record_id(8) + timestamp(8)


# ─────────────────────────────────────────────
#  Типы данных
# ─────────────────────────────────────────────

@dataclass
class EvtxHit:
    """Одна найденная запись журнала, содержащая серийник."""
    log_path:    Path
    record_id:   int
    chunk_index: int
    record_offset_in_file: int   # абсолютный offset в файле
    record_size: int
    xml_snippet: str             # первые 300 символов XML для отчёта
    zeroed:      bool = False
    error:       Optional[str]   = None


@dataclass
class EvtxResult:
    """Итог обработки одного .evtx файла."""
    log_path:    Path
    hits:        list[EvtxHit]          = field(default_factory=list)
    backed_up:   bool                   = False
    backup_path: Optional[Path]         = None
    error:       Optional[str]          = None

    @property
    def found(self) -> bool:
        return len(self.hits) > 0

    @property
    def zeroed_count(self) -> int:
        return sum(1 for h in self.hits if h.zeroed)


# ─────────────────────────────────────────────
#  Вспомогательные функции — CRC
# ─────────────────────────────────────────────

def _crc32_bytes(data: bytes) -> int:
    """CRC32 в формате EVTX (unsigned, little-endian)."""
    return crc32(data) & 0xFFFFFFFF


def _recalculate_chunk_checksums(mm: mmap.mmap, chunk_abs_offset: int) -> None:
    """
    Пересчитывает оба CRC32 чанка и записывает их обратно в mmap.

    chunk header CRC покрывает:
      bytes [0..127] + bytes [132..511] чанка
    records CRC покрывает:
      bytes [512..65535] чанка (зона записей)
    """
    base = chunk_abs_offset

    # ── Records CRC (offset 124 в chunk header) ───────────────────────────────
    records_zone = mm[base + EVTX_CHUNK_HEADER_SIZE : base + EVTX_CHUNK_SIZE]
    records_crc  = _crc32_bytes(records_zone)
    struct.pack_into("<I", mm, base + CHUNK_HEADER_OFFSET_RECORDS_CRC, records_crc)

    # ── Header CRC (offset 128 в chunk header) ────────────────────────────────
    header_part1 = mm[base + 0   : base + 128]
    header_part2 = mm[base + 132 : base + 512]
    header_crc   = _crc32_bytes(header_part1 + header_part2)
    struct.pack_into("<I", mm, base + CHUNK_HEADER_OFFSET_HEADER_CRC, header_crc)


# ─────────────────────────────────────────────
#  Низкоуровневый парсер записей
# ─────────────────────────────────────────────

def _iter_records_in_chunk(
    mm: mmap.mmap,
    chunk_abs_offset: int,
    chunk_size: int = EVTX_CHUNK_SIZE,
) -> list[tuple[int, int]]:
    """
    Возвращает список (record_abs_offset, record_size) для всех записей в чанке.
    Не использует python-evtx — чистый бинарный обход.
    """
    records: list[tuple[int, int]] = []
    pos = chunk_abs_offset + EVTX_CHUNK_HEADER_SIZE
    end = chunk_abs_offset + chunk_size

    while pos + RECORD_HEADER_SIZE <= end:
        magic = mm[pos : pos + 4]
        if magic != EVTX_RECORD_MAGIC:
            break

        rec_size = struct.unpack_from("<I", mm, pos + 4)[0]
        if rec_size < RECORD_HEADER_SIZE or pos + rec_size > end:
            break

        records.append((pos, rec_size))
        pos += rec_size

    return records


# ─────────────────────────────────────────────
#  Zeroing одной записи
# ─────────────────────────────────────────────

def _zero_record_data(
    mm: mmap.mmap,
    record_abs_offset: int,
    record_size: int,
) -> None:
    """
    Затирает Data-зону записи нулями.
    Сохраняем:
      - первые 4 байта (magic 0x00002A2A)
      - байты 4..7    (size, чтобы следующий парсер мог пропустить запись)
      - байты 8..15   (record_id)
      - байты 16..23  (timestamp)
    Затираем:
      - байты 24..(record_size - 5)  — BinXML payload
      - последние 4 байта = копия record_size (trailing size) — обнуляем тоже
    """
    zero_start = record_abs_offset + RECORD_HEADER_SIZE
    zero_end   = record_abs_offset + record_size
    zero_len   = zero_end - zero_start

    if zero_len > 0:
        mm[zero_start:zero_end] = b"\x00" * zero_len


# ─────────────────────────────────────────────
#  Основная логика — один файл
# ─────────────────────────────────────────────

def _process_evtx_file(
    log_path: Path,
    serial: str,
    backup_dir: Optional[Path],
    dry_run: bool,
) -> EvtxResult:
    result = EvtxResult(log_path=log_path)

    if not log_path.exists():
        result.error = "file not found"
        return result

    # ── Шаг 1: python-evtx парсинг для поиска серийника ──────────────────────
    if not EVTX_AVAILABLE:
        result.error = "python-evtx not installed"
        return result

    serial_upper = serial.upper()
    hit_offsets: list[tuple[int, int, int, str]] = []
    # (chunk_index, record_abs_offset, record_size, xml_snippet)

    try:
        with evtx_lib.Evtx(str(log_path)) as log:
            for chunk_index, chunk in enumerate(log.chunks()):
                for record in chunk.records():
                    try:
                        xml = evtx_views.evtx_record_xml_view(record)
                    except Exception:
                        continue

                    if serial_upper in xml.upper():
                        snippet = xml[:300].replace("\n", " ")
                        rec_id  = record.record_num()
                        # python-evtx даёт offset относительно начала файла
                        rec_offset = record.offset()
                        rec_size   = record.length()

                        hit = EvtxHit(
                            log_path=log_path,
                            record_id=rec_id,
                            chunk_index=chunk_index,
                            record_offset_in_file=rec_offset,
                            record_size=rec_size,
                            xml_snippet=snippet,
                        )
                        result.hits.append(hit)
                        hit_offsets.append(
                            (chunk_index, rec_offset, rec_size, snippet)
                        )
    except Exception as exc:
        result.error = f"parse error: {exc}"
        return result

    if not result.hits:
        return result   # серийник не найден — выходим

    # ── Шаг 2: бэкап ─────────────────────────────────────────────────────────
    if backup_dir and not dry_run:
        backup_dir.mkdir(parents=True, exist_ok=True)
        dst = backup_dir / log_path.name
        try:
            shutil.copy2(log_path, dst)
            result.backed_up   = True
            result.backup_path = dst
        except Exception as exc:
            result.error = f"backup failed: {exc}"
            return result

    if dry_run:
        # dry_run — только помечаем, не трогаем файл
        return result

    # ── Шаг 3: zeroing через mmap ─────────────────────────────────────────────
    affected_chunks: set[int] = set()

    try:
        with open(log_path, "r+b") as fh:
            mm = mmap.mmap(fh.fileno(), 0)

            for hit, (chunk_idx, rec_offset, rec_size, _) in zip(
                result.hits, hit_offsets
            ):
                try:
                    _zero_record_data(mm, rec_offset, rec_size)
                    hit.zeroed = True
                    affected_chunks.add(chunk_idx)
                except Exception as exc:
                    hit.error = f"zero failed: {exc}"

            # ── Шаг 4: пересчёт CRC для каждого затронутого чанка ────────────
            for chunk_idx in affected_chunks:
                chunk_abs = EVTX_FILE_HEADER_SIZE + chunk_idx * EVTX_CHUNK_SIZE
                try:
                    _recalculate_chunk_checksums(mm, chunk_abs)
                except Exception as exc:
                    result.error = (result.error or "") + \
                        f" | crc recalc chunk {chunk_idx}: {exc}"

            mm.flush()
            mm.close()

    except Exception as exc:
        result.error = f"mmap write failed: {exc}"

    return result


# ─────────────────────────────────────────────
#  Публичный API
# ─────────────────────────────────────────────

# Журналы, которые сканируем по умолчанию
DEFAULT_EVTX_LOGS: list[str] = [
    r"C:\Windows\System32\winevt\Logs\System.evtx",
    r"C:\Windows\System32\winevt\Logs\Security.evtx",
    r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-DriverFrameworks-UserMode%4Operational.evtx",
    r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-Kernel-PnP%4Configuration.evtx",
    r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-WPD-MTPClassDriver%4Operational.evtx",
]


def process_event_logs(
    serial: str,
    backup_dir: Optional[Path] = None,
    extra_logs: Optional[list[Path]] = None,
    dry_run: bool = False,
) -> list[EvtxResult]:
    """
    Точка входа для eventlog-модуля.

    Args:
        serial:     Серийник USB-устройства (регистр не важен).
        backup_dir: Папка для бэкапов .evtx до модификации.
        extra_logs: Дополнительные .evtx файлы помимо DEFAULT_EVTX_LOGS.
        dry_run:    Только поиск — файлы не изменяются.

    Returns:
        Список EvtxResult — по одному на каждый проверенный файл.
    """
    all_paths: list[Path] = [Path(p) for p in DEFAULT_EVTX_LOGS]
    if extra_logs:
        all_paths.extend(extra_logs)

    results: list[EvtxResult] = []
    for log_path in all_paths:
        r = _process_evtx_file(log_path, serial, backup_dir, dry_run)
        results.append(r)

    return results


def summary(results: list[EvtxResult]) -> dict:
    """
    Краткая сводка по всем результатам — для отчёта / Rich-таблицы.

    Returns:
        {
          "scanned":  int,   # сколько файлов проверено
          "with_hits": int,  # в скольких найден серийник
          "zeroed":   int,   # сколько записей обнулено
          "errors":   list[str]
        }
    """
    scanned   = len(results)
    with_hits = sum(1 for r in results if r.found)
    zeroed    = sum(r.zeroed_count for r in results)
    errors    = [
        f"{r.log_path.name}: {r.error}"
        for r in results if r.error
    ]
    return {
        "scanned":   scanned,
        "with_hits": with_hits,
        "zeroed":    zeroed,
        "errors":    errors,
    }
