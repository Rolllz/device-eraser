# modules/ese.py
"""
ESE module — поиск следов USB-устройства в базах данных ESE (.edb).

Покрываемые артефакты:
  - Windows Search DB : C:/ProgramData/Microsoft/Search/Data/Applications/Windows/Windows.edb
  - SRUM DB           : C:/Windows/System32/sru/SruDb.dat

Платформа: Linux Live CD — только кросс-платформенные инструменты.

Зависимости:
  pip install libesedb-python   # официальная Python-обёртка для libesedb
  # или: pip install dissect.esedb  (pure-python, не требует компиляции)

libesedb-python требует сборки нативной либы:
  apt install libesedb-dev   / или собрать из исходников
  https://github.com/libyal/libesedb

dissect.esedb — предпочтительно для Live CD, без нативных зависимостей:
  pip install dissect.esedb
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Optional

# ── Пробуем dissect.esedb (pure-python, предпочтительно) ─────────────────────
try:
    from dissect.esedb import EseDB
    DISSECT_AVAILABLE = True
except ImportError:
    DISSECT_AVAILABLE = False

# ── Фоллбэк: libesedb-python (требует нативной сборки) ───────────────────────
if not DISSECT_AVAILABLE:
    try:
        import libesedb
        LIBESEDB_AVAILABLE = True
    except ImportError:
        LIBESEDB_AVAILABLE = False
else:
    LIBESEDB_AVAILABLE = False


# ─────────────────────────────────────────────
#  Типы данных
# ─────────────────────────────────────────────

@dataclass
class EseHit:
    """Одна найденная запись ESE, содержащая серийник."""
    db_path: Path          # путь к .edb файлу
    table: str             # имя таблицы
    row_index: int         # индекс строки
    column: str            # имя колонки
    matched_value: str     # значение, где найден серийник


@dataclass
class EseResult:
    """Итог работы модуля."""
    hits: list[EseHit] = field(default_factory=list)
    cleaned: list[Path] = field(default_factory=list)   # удалённые / обнулённые файлы
    errors: list[str]  = field(default_factory=list)


# ─────────────────────────────────────────────
#  Целевые базы данных
# ─────────────────────────────────────────────

# Пути относительно корня смонтированного Windows-раздела
_TARGET_DBS: list[str] = [
    "ProgramData/Microsoft/Search/Data/Applications/Windows/Windows.edb",
    "Windows/System32/sru/SruDb.dat",
]

# Таблицы Windows Search, которые могут содержать пути к файлам
_SEARCH_TABLES = {
    "SystemIndex_Gthr",
    "SystemIndex_GthrPth",
    "SystemIndex_PropertyStore",
}

# Таблицы SRUM
_SRUM_TABLES = {
    "SruDbIdMapTable",
    "{5C8CF1C7-7257-4F13-B223-970EF5939312}",  # App Timeline
    "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}",  # Network Usage
    "{DD6636C4-8929-4683-974E-22C046A43763}",  # Connected Standby
}


# ─────────────────────────────────────────────
#  Вспомогательные функции
# ─────────────────────────────────────────────

def _value_to_str(value) -> str:
    """Приводим любое значение колонки к строке для поиска серийника."""
    if value is None:
        return ""
    if isinstance(value, (bytes, bytearray)):
        try:
            return value.decode("utf-16-le", errors="ignore")
        except Exception:
            return value.decode("latin-1", errors="ignore")
    return str(value)


def _serial_in(text: str, serial: str) -> bool:
    """Регистронезависимый поиск серийника в строке."""
    return serial.lower() in text.lower()


# ─────────────────────────────────────────────
#  Парсер через dissect.esedb (предпочтительно)
# ─────────────────────────────────────────────

def _scan_db_dissect(
    db_path: Path,
    serial: str,
    target_tables: Optional[set[str]],
    result: EseResult,
) -> None:
    """Сканируем .edb через dissect.esedb, собираем EseHit'ы."""
    try:
        with open(db_path, "rb") as fh:
            db = EseDB(fh)

            for table in db.tables():
                tname = table.name

                # Если задан фильтр таблиц — пропускаем остальные
                if target_tables and tname not in target_tables:
                    continue

                try:
                    for row_idx, record in enumerate(table.records()):
                        for col in table.columns:
                            try:
                                raw = record.get(col.name)
                            except Exception:
                                continue

                            text = _value_to_str(raw)
                            if not text:
                                continue

                            if _serial_in(text, serial):
                                result.hits.append(EseHit(
                                    db_path=db_path,
                                    table=tname,
                                    row_index=row_idx,
                                    column=col.name,
                                    matched_value=text[:200],  # обрезаем для лога
                                ))
                except Exception as e:
                    result.errors.append(
                        f"[ese] Таблица {tname} в {db_path}: {e}"
                    )

    except Exception as e:
        result.errors.append(f"[ese] Не удалось открыть {db_path}: {e}")


# ─────────────────────────────────────────────
#  Парсер через libesedb (фоллбэк)
# ─────────────────────────────────────────────

def _scan_db_libesedb(
    db_path: Path,
    serial: str,
    target_tables: Optional[set[str]],
    result: EseResult,
) -> None:
    """Сканируем .edb через libesedb-python."""
    try:
        db = libesedb.file()
        db.open(str(db_path))

        for t_idx in range(db.get_number_of_tables()):
            table = db.get_table(t_idx)
            tname = table.get_name()

            if target_tables and tname not in target_tables:
                continue

            num_cols    = table.get_number_of_columns()
            col_names   = [table.get_column(i).get_name() for i in range(num_cols)]

            try:
                for row_idx in range(table.get_number_of_records()):
                    record = table.get_record(row_idx)
                    for col_idx, col_name in enumerate(col_names):
                        try:
                            raw = record.get_value_data(col_idx)
                        except Exception:
                            continue

                        text = _value_to_str(raw)
                        if not text:
                            continue

                        if _serial_in(text, serial):
                            result.hits.append(EseHit(
                                db_path=db_path,
                                table=tname,
                                row_index=row_idx,
                                column=col_name,
                                matched_value=text[:200],
                            ))
            except Exception as e:
                result.errors.append(
                    f"[ese] Таблица {tname} в {db_path}: {e}"
                )

        db.close()

    except Exception as e:
        result.errors.append(f"[ese] Не удалось открыть {db_path}: {e}")


# ─────────────────────────────────────────────
#  Стратегия очистки
# ─────────────────────────────────────────────

def _clean_db(db_path: Path, result: EseResult, dry_run: bool) -> None:
    """
    Стратегия для ESE: удаляем весь файл БД.

    Почему не zeroing отдельных записей?
      - ESE — сложная B-tree структура с транзакционным журналом.
      - Частичное затирание ломает контрольные суммы страниц.
      - Восстановление из теней (VSS) всё равно поднимет старый файл.
      - Проще и безопаснее удалить весь .edb.
      - Побочный эффект: Windows Search переиндексирует при следующей загрузке —
        новый индекс не будет содержать артефактов.
    """
    if dry_run:
        result.cleaned.append(db_path)
        return

    try:
        db_path.unlink(missing_ok=True)
        result.cleaned.append(db_path)

        # Удаляем журналы транзакций (.log) рядом с БД —
        # они тоже могут содержать пути к файлам в незакоммиченных транзакциях
        parent = db_path.parent
        for log_file in parent.glob("*.log"):
            log_file.unlink(missing_ok=True)
        for log_file in parent.glob("*.jrs"):
            log_file.unlink(missing_ok=True)
        for chk_file in parent.glob("*.chk"):
            chk_file.unlink(missing_ok=True)

    except Exception as e:
        result.errors.append(f"[ese] Ошибка удаления {db_path}: {e}")


# ─────────────────────────────────────────────
#  Публичный API
# ─────────────────────────────────────────────

def scan_and_clean(
    windows_root: Path,
    serial: str,
    dry_run: bool = False,
) -> EseResult:
    """
    Сканирует все целевые ESE-базы на смонтированном Windows-разделе.

    Параметры
    ----------
    windows_root : Path
        Корень смонтированного раздела, например Path("/mnt/windows").
    serial : str
        Серийный номер USB-устройства (частичное совпадение, без учёта регистра).
    dry_run : bool
        Если True — только находит, не удаляет.

    Возвращает
    ----------
    EseResult с полями hits / cleaned / errors.
    """
    if not DISSECT_AVAILABLE and not LIBESEDB_AVAILABLE:
        result = EseResult()
        result.errors.append(
            "[ese] Нет доступных парсеров. "
            "Установи: pip install dissect.esedb  "
            "или собери libesedb + pip install libesedb-python"
        )
        return result

    result = EseResult()

    for rel_path in _TARGET_DBS:
        db_path = windows_root / rel_path

        if not db_path.exists():
            continue

        # Определяем фильтр таблиц по типу БД
        if "Windows.edb" in db_path.name:
            target_tables = _SEARCH_TABLES
        elif "SruDb.dat" in db_path.name:
            target_tables = _SRUM_TABLES
        else:
            target_tables = None  # сканируем все таблицы

        # Выбираем доступный бэкенд
        if DISSECT_AVAILABLE:
            _scan_db_dissect(db_path, serial, target_tables, result)
        else:
            _scan_db_libesedb(db_path, serial, target_tables, result)

        # Если нашли хиты — чистим
        db_hits = [h for h in result.hits if h.db_path == db_path]
        if db_hits:
            _clean_db(db_path, result, dry_run)

    return result


# ─────────────────────────────────────────────
#  Быстрый ручной тест
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print("Использование: python ese.py <windows_root> <serial>")
        print("Пример:        python ese.py /mnt/win  AA12345678")
        sys.exit(1)

    root   = Path(sys.argv[1])
    serial = sys.argv[2]

    res = scan_and_clean(root, serial, dry_run=True)

    print(f"\n=== ESE SCAN (dry_run) ===")
    print(f"Найдено хитов : {len(res.hits)}")
    for h in res.hits:
        print(f"  [{h.db_path.name}] {h.table}.{h.column} "
              f"(row {h.row_index}): {h.matched_value[:80]!r}")

    print(f"\nБудет удалено : {len(res.cleaned)}")
    for p in res.cleaned:
        print(f"  {p}")

    if res.errors:
        print(f"\nОшибки ({len(res.errors)}):")
        for e in res.errors:
            print(f"  {e}")
