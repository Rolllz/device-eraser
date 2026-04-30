#!/usr/bin/env python3
# device_eraser.py
"""
USB Device Artifact Eraser — главный оркестратор.

Платформа : Linux Live CD
Python     : 3.8+
Зависимости: см. requirements.txt (python-registry, python-evtx, pylnk3)

Использование:
  sudo python3 device_eraser.py --drive /mnt/windows --serial "XXXXXXXXX"
  sudo python3 device_eraser.py --drive /mnt/windows --serial "XXXXXXXXX" --dry-run
  sudo python3 device_eraser.py --drive /mnt/windows --serial "XXXXXXXXX" --verbose

Аргументы:
  --drive     Точка монтирования Windows-раздела  (обязательно)
  --serial    Серийный номер USB-устройства        (обязательно)
  --dry-run   Только поиск, без записи изменений   (опционально)
  --verbose   Подробный вывод в консоль            (опционально)
  --log       Путь к лог-файлу  (по умолчанию: eraser.log)
  --no-log    Не писать лог-файл вообще

Модули:
  modules/registry.py    — кусты реестра (.hiv / SAM / SYSTEM / SOFTWARE / NTUSER.DAT)
  modules/eventlog.py    — журналы событий (.evtx)
  modules/filesystem.py  — ФС-артефакты (LNK, Prefetch, Thumbcache, setupapi.dev.log)
  modules/ese.py         — базы ESE (Windows.edb, SruDb.dat)
"""

import argparse
import logging
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

# ── Импорт модулей ─────────────────────────────────────────────────────────────
try:
    from modules.registry   import RegistryCleaner
    from modules.eventlog   import EventLogCleaner
    from modules.filesystem import FilesystemCleaner
    from modules.ese        import ESECleaner
except ImportError as exc:
    print(f"[FATAL] Не удалось импортировать модуль: {exc}")
    print("        Убедись, что папка modules/ находится рядом с device_eraser.py")
    sys.exit(1)


# ══════════════════════════════════════════════════════════════════════════════
# Dataclass результата
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class ModuleResult:
    """Результат работы одного модуля."""
    name        : str
    success     : bool
    found       : int = 0          # количество найденных совпадений
    erased      : int = 0          # количество обработанных артефактов
    errors      : List[str] = field(default_factory=list)
    duration_s  : float = 0.0


@dataclass
class EraserReport:
    """Итоговый отчёт по всем модулям."""
    serial      : str
    drive       : str
    dry_run     : bool
    results     : List[ModuleResult] = field(default_factory=list)
    total_found : int = 0
    total_erased: int = 0
    start_time  : float = field(default_factory=time.time)
    end_time    : float = 0.0

    # ── computed helpers ──────────────────────────────────────────────────────
    @property
    def duration(self) -> float:
        return self.end_time - self.start_time

    @property
    def all_ok(self) -> bool:
        return all(r.success for r in self.results)


# ══════════════════════════════════════════════════════════════════════════════
# Логирование
# ══════════════════════════════════════════════════════════════════════════════

def setup_logging(verbose: bool, log_path: str | None) -> logging.Logger:
    """
    Настраивает корневой логгер.

    verbose=True  → уровень DEBUG в консоль
    verbose=False → уровень INFO  в консоль
    log_path      → уровень DEBUG в файл (всегда полный лог)
    """
    logger  = logging.getLogger("eraser")
    logger.setLevel(logging.DEBUG)

    fmt_console = logging.Formatter(
        "%(levelname)-8s %(message)s"
    )
    fmt_file = logging.Formatter(
        "%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # — консольный хендлер —
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG if verbose else logging.INFO)
    ch.setFormatter(fmt_console)
    logger.addHandler(ch)

    # — файловый хендлер —
    if log_path:
        try:
            fh = logging.FileHandler(log_path, encoding="utf-8")
            fh.setLevel(logging.DEBUG)
            fh.setFormatter(fmt_file)
            logger.addHandler(fh)
        except OSError as exc:
            logger.warning(f"Не удалось открыть лог-файл '{log_path}': {exc}")

    return logger


# ══════════════════════════════════════════════════════════════════════════════
# Аргументы CLI
# ══════════════════════════════════════════════════════════════════════════════

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="device_eraser.py",
        description="USB Device Artifact Eraser — удаляет следы USB с смонтированного Windows-раздела.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры:
  sudo python3 device_eraser.py --drive /mnt/win --serial "ABC123XYZ"
  sudo python3 device_eraser.py --drive /mnt/win --serial "ABC123XYZ" --dry-run --verbose
  sudo python3 device_eraser.py --drive /mnt/win --serial "ABC123XYZ" --log /tmp/report.log
        """,
    )

    parser.add_argument(
        "--drive",
        required=True,
        metavar="PATH",
        help="Точка монтирования Windows-раздела (например, /mnt/windows)",
    )
    parser.add_argument(
        "--serial",
        required=True,
        metavar="SERIAL",
        help="Серийный номер USB-устройства (частичное совпадение поддерживается)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Только поиск; не вносить никаких изменений",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        default=False,
        help="Подробный вывод (DEBUG-уровень в консоль)",
    )

    log_group = parser.add_mutually_exclusive_group()
    log_group.add_argument(
        "--log",
        metavar="FILE",
        default="eraser.log",
        help="Путь к лог-файлу (по умолчанию: eraser.log)",
    )
    log_group.add_argument(
        "--no-log",
        action="store_true",
        default=False,
        help="Не писать лог-файл",
    )

    return parser.parse_args()


# ══════════════════════════════════════════════════════════════════════════════
# Валидация входных данных
# ══════════════════════════════════════════════════════════════════════════════

def validate_inputs(args: argparse.Namespace, logger: logging.Logger) -> bool:
    """Проверяет корректность аргументов перед запуском модулей."""
    ok = True

    # Точка монтирования должна существовать
    drive = Path(args.drive)
    if not drive.exists():
        logger.error(f"Путь не существует: {drive}")
        ok = False
    elif not drive.is_dir():
        logger.error(f"Путь не является директорией: {drive}")
        ok = False
    else:
        # Минимальная проверка: ожидаем папку Windows внутри
        win_dir = drive / "Windows"
        if not win_dir.exists():
            logger.warning(
                f"Папка 'Windows' не найдена в '{drive}'. "
                f"Убедись, что раздел смонтирован правильно."
            )
            # Не фатальная ошибка — продолжаем

    # Серийник не должен быть пустым
    if not args.serial or not args.serial.strip():
        logger.error("Серийный номер не может быть пустым (--serial)")
        ok = False

    return ok


# ══════════════════════════════════════════════════════════════════════════════
# Запуск одного модуля с перехватом исключений
# ══════════════════════════════════════════════════════════════════════════════

def run_module(
    name        : str,
    cleaner_cls ,
    drive       : str,
    serial      : str,
    dry_run     : bool,
    logger      : logging.Logger,
) -> ModuleResult:
    """
    Создаёт экземпляр cleaner_cls, вызывает .run() и возвращает ModuleResult.

    Ожидаемый интерфейс каждого Cleaner-класса:
        cleaner = SomeCleaner(drive, serial, dry_run, logger)
        result  = cleaner.run()   # → {"found": int, "erased": int, "errors": [...]}
    """
    result = ModuleResult(name=name, success=False)
    t_start = time.perf_counter()

    logger.info(f"{'─' * 60}")
    logger.info(f"[{name}] Запуск...")

    try:
        cleaner     = cleaner_cls(drive, serial, dry_run, logger)
        raw         = cleaner.run()

        result.found  = raw.get("found",  0)
        result.erased = raw.get("erased", 0)
        result.errors = raw.get("errors", [])
        result.success = True

        if result.errors:
            logger.warning(
                f"[{name}] Завершено с {len(result.errors)} ошибкой(-ями). "
                f"Найдено: {result.found}, обработано: {result.erased}"
            )
        else:
            logger.info(
                f"[{name}] OK — найдено: {result.found}, "
                f"{'(dry-run, не изменено)' if dry_run else f'обработано: {result.erased}'}"
            )

    except Exception as exc:
        result.success = False
        result.errors.append(str(exc))
        logger.error(f"[{name}] КРИТИЧЕСКАЯ ОШИБКА: {exc}", exc_info=True)

    finally:
        result.duration_s = time.perf_counter() - t_start
        logger.debug(f"[{name}] Время выполнения: {result.duration_s:.2f}s")

    return result


# ══════════════════════════════════════════════════════════════════════════════
# Итоговый отчёт
# ══════════════════════════════════════════════════════════════════════════════

def print_report(report: EraserReport, logger: logging.Logger) -> None:
    """Выводит сводную таблицу результатов."""
    logger.info("")
    logger.info("═" * 60)
    logger.info("  ИТОГОВЫЙ ОТЧЁТ")
    logger.info("═" * 60)
    logger.info(f"  Серийник   : {report.serial}")
    logger.info(f"  Раздел     : {report.drive}")
    logger.info(f"  Режим      : {'DRY-RUN (без изменений)' if report.dry_run else 'ЗАПИСЬ'}")
    logger.info(f"  Длительность: {report.duration:.1f}s")
    logger.info("")
    logger.info(f"  {'Модуль':<30} {'Найдено':>8} {'Обработано':>11} {'Статус':>10}")
    logger.info(f"  {'─'*30} {'─'*8} {'─'*11} {'─'*10}")

    for r in report.results:
        status = "OK" if r.success else f"ОШИБКА ({len(r.errors)})"
        erased_col = "—" if report.dry_run else str(r.erased)
        logger.info(
            f"  {r.name:<30} {r.found:>8} {erased_col:>11} {status:>10}"
        )
        for err in r.errors:
            logger.debug(f"    ↳ {err}")

    logger.info(f"  {'─'*30} {'─'*8} {'─'*11} {'─'*10}")
    logger.info(
        f"  {'ИТОГО':<30} {report.total_found:>8} "
        f"{'—' if report.dry_run else str(report.total_erased):>11}"
    )
    logger.info("═" * 60)

    if not report.all_ok:
        logger.warning("  Один или несколько модулей завершились с ошибкой.")
        logger.warning("  Проверь лог-файл для деталей.")
    else:
        logger.info("  Все модули завершились успешно. ✓")

    logger.info("")


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main() -> int:
    args   = parse_args()
    log_path = None if args.no_log else args.log
    logger   = setup_logging(args.verbose, log_path)

    # ── Баннер ────────────────────────────────────────────────────────────────
    logger.info("═" * 60)
    logger.info("  USB Device Artifact Eraser")
    logger.info("  Платформа: Linux Live CD | Python 3.8+")
    logger.info("═" * 60)
    if args.dry_run:
        logger.info("  ⚑  DRY-RUN режим — изменения НЕ записываются")
        logger.info("─" * 60)

    # ── Валидация ─────────────────────────────────────────────────────────────
    if not validate_inputs(args, logger):
        logger.error("Ошибка валидации входных данных. Выход.")
        return 2

    logger.info(f"  Серийник : {args.serial}")
    logger.info(f"  Раздел   : {args.drive}")
    if log_path:
        logger.info(f"  Лог-файл : {log_path}")

    # ── Порядок запуска модулей ───────────────────────────────────────────────
    # Порядок важен: сначала реестр и журналы, потом файловая система и ESE.
    # Изменение порядка не нарушит корректность, но логически удобнее так.
    MODULES = [
        ("Registry",    RegistryCleaner),
        ("EventLog",    EventLogCleaner),
        ("Filesystem",  FilesystemCleaner),
        ("ESE",         ESECleaner),
    ]

    report = EraserReport(
        serial  = args.serial,
        drive   = args.drive,
        dry_run = args.dry_run,
    )

    # ── Запуск модулей ────────────────────────────────────────────────────────
    for mod_name, mod_cls in MODULES:
        result = run_module(
            name        = mod_name,
            cleaner_cls = mod_cls,
            drive       = args.drive,
            serial      = args.serial,
            dry_run     = args.dry_run,
            logger      = logger,
        )
        report.results.append(result)
        report.total_found  += result.found
        report.total_erased += result.erased

    report.end_time = time.time()

    # ── Отчёт ─────────────────────────────────────────────────────────────────
    print_report(report, logger)

    # ── Код возврата ──────────────────────────────────────────────────────────
    # 0 = всё OK
    # 1 = один или несколько модулей с ошибкой
    # 2 = фатальная ошибка до запуска модулей
    return 0 if report.all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
