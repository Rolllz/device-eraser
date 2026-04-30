# modules/registry.py
"""
Registry module — поиск и удаление следов USB-устройства в хайвах реестра.

Покрываемые хайвы:
  - SYSTEM   → USBSTOR, USB, MountedDevices, DeviceClasses
  - SOFTWARE → Windows Portable Devices, AutoRun
  - NTUSER.DAT → MountPoints2

Стратегия:
  - Онлайн-хайвы (живая система) : winreg
  - Офлайн-хайвы (файл)          : python-registry (Registry)
"""

from __future__ import annotations

import os
import shutil
import winreg
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# pip install python-registry
try:
    from Registry import Registry as LibRegistry
    OFFLINE_AVAILABLE = True
except ImportError:
    OFFLINE_AVAILABLE = False


# ─────────────────────────────────────────────
#  Типы данных
# ─────────────────────────────────────────────

@dataclass
class RegistryHit:
    """Одна найденная запись реестра, содержащая серийник."""
    hive: str          # "SYSTEM" | "SOFTWARE" | "NTUSER.DAT"
    key_path: str      # полный путь ключа
    value_name: str    # имя значения (или "" если сам ключ)
    match_context: str # фрагмент, где найден серийник


@dataclass
class RegistryResult:
    """Итог работы модуля."""
    hits: list[RegistryHit] = field(default_factory=list)
    deleted_keys: list[str] = field(default_factory=list)
    deleted_values: list[str] = field(default_factory=list)
    errors: list[str]        = field(default_factory=list)
    backed_up: bool = False


# ─────────────────────────────────────────────
#  Целевые ключи реестра
# ─────────────────────────────────────────────

# (хайв-константа winreg, путь, удалять_ключ_целиком)
SYSTEM_KEYS: list[tuple] = [
    # USBSTOR — главный источник серийников
    (winreg.HKEY_LOCAL_MACHINE,
     r"SYSTEM\CurrentControlSet\Enum\USBSTOR", True),
    (winreg.HKEY_LOCAL_MACHINE,
     r"SYSTEM\ControlSet001\Enum\USBSTOR", True),
    (winreg.HKEY_LOCAL_MACHINE,
     r"SYSTEM\ControlSet002\Enum\USBSTOR", True),

    # USB (VID/PID уровень)
    (winreg.HKEY_LOCAL_MACHINE,
     r"SYSTEM\CurrentControlSet\Enum\USB", False),
    (winreg.HKEY_LOCAL_MACHINE,
     r"SYSTEM\ControlSet001\Enum\USB", False),

    # MountedDevices — бинарные значения с серийником
    (winreg.HKEY_LOCAL_MACHINE,
     r"SYSTEM\MountedDevices", False),

    # DeviceClasses — GUID дисковых устройств
    (winreg.HKEY_LOCAL_MACHINE,
     r"SYSTEM\CurrentControlSet\Control\DeviceClasses\\"
     r"{53f56307-b6bf-11d0-94f2-00a0c91efb8b}", True),
]

SOFTWARE_KEYS: list[tuple] = [
    # Windows Portable Devices (WPD)
    (winreg.HKEY_LOCAL_MACHINE,
     r"SOFTWARE\Microsoft\Windows Portable Devices\Devices", True),

    # AutoRun / Shell Hardware Detection
    (winreg.HKEY_LOCAL_MACHINE,
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
     r"\AutoplayHandlers\DeviceHandlers", False),
]

NTUSER_KEY_PATHS: list[str] = [
    # MountPoints2 — буква диска ↔ серийник
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2",
]


# ─────────────────────────────────────────────
#  Вспомогательные функции
# ─────────────────────────────────────────────

def _serial_in_string(serial: str, text: str) -> bool:
    """Регистронезависимый поиск серийника в строке."""
    return serial.lower() in text.lower()


def _backup_key(hive_root: int, key_path: str, backup_dir: Path) -> None:
    """
    Экспортирует ключ реестра в .reg файл через reg.exe.
    Используется только как дополнительный бэкап —
    основной бэкап директорий делает orchestrator.
    """
    hive_map = {
        winreg.HKEY_LOCAL_MACHINE: "HKLM",
        winreg.HKEY_CURRENT_USER:  "HKCU",
        winreg.HKEY_USERS:         "HKU",
    }
    hive_str = hive_map.get(hive_root, "HKLM")
    safe_name = key_path.replace("\\", "_").replace("/", "_")[:80]
    out_file = backup_dir / f"{hive_str}__{safe_name}.reg"

    os.system(
        f'reg export "{hive_str}\\{key_path}" "{out_file}" /y >nul 2>&1'
    )


def _iter_subkeys(hkey) -> list[str]:
    """Возвращает список имён подключей."""
    names = []
    i = 0
    while True:
        try:
            names.append(winreg.EnumKey(hkey, i))
            i += 1
        except OSError:
            break
    return names


def _iter_values(hkey) -> list[tuple[str, object, int]]:
    """Возвращает список (имя, данные, тип) для всех значений."""
    vals = []
    i = 0
    while True:
        try:
            vals.append(winreg.EnumValue(hkey, i))
            i += 1
        except OSError:
            break
    return vals


def _delete_key_tree(hive_root: int, key_path: str) -> None:
    """Рекурсивно удаляет ключ и все подключи."""
    try:
        # winreg.DeleteKeyEx поддерживает только пустые ключи →
        # используем reg.exe для рекурсивного удаления
        hive_map = {
            winreg.HKEY_LOCAL_MACHINE: "HKLM",
            winreg.HKEY_CURRENT_USER:  "HKCU",
            winreg.HKEY_USERS:         "HKU",
        }
        hive_str = hive_map.get(hive_root, "HKLM")
        os.system(
            f'reg delete "{hive_str}\\{key_path}" /f >nul 2>&1'
        )
    except Exception:
        pass


# ─────────────────────────────────────────────
#  Онлайн-поиск (winreg — живая система)
# ─────────────────────────────────────────────

def _search_online_key(
    hive_root: int,
    key_path: str,
    serial: str,
    delete_whole: bool,
    backup_dir: Optional[Path],
    result: RegistryResult,
) -> None:
    """
    Открывает ключ, ищет серийник в подключах и значениях.
    Если найден:
      - delete_whole=True  → удаляет весь ключ (и подключи)
      - delete_whole=False → удаляет только конкретные значения/подключи
    """
    try:
        root_hkey = winreg.OpenKey(
            hive_root, key_path,
            0, winreg.KEY_READ | winreg.KEY_ENUMERATE_SUB_KEYS
        )
    except FileNotFoundError:
        return  # ключ не существует — норма
    except PermissionError as e:
        result.errors.append(f"PermissionError: {key_path} → {e}")
        return

    with root_hkey:
        subkey_names = _iter_subkeys(root_hkey)

    for sub in subkey_names:
        full_path = f"{key_path}\\{sub}"

        # Серийник может быть прямо в имени подключа
        if _serial_in_string(serial, sub):
            result.hits.append(RegistryHit(
                hive=_hive_name(hive_root),
                key_path=full_path,
                value_name="",
                match_context=f"subkey name: {sub}",
            ))
            if backup_dir:
                _backup_key(hive_root, full_path, backup_dir)
            _delete_key_tree(hive_root, full_path)
            result.deleted_keys.append(full_path)
            continue

        # Иначе смотрим значения внутри подключа
        try:
            sub_hkey = winreg.OpenKey(
                hive_root, full_path,
                0, winreg.KEY_READ
            )
        except OSError:
            continue

        with sub_hkey:
            values = _iter_values(sub_hkey)

        for val_name, val_data, val_type in values:
            data_str = ""
            if isinstance(val_data, str):
                data_str = val_data
            elif isinstance(val_data, bytes):
                # бинарные данные — ищем серийник как байты
                try:
                    data_str = val_data.decode("utf-16-le", errors="ignore")
                except Exception:
                    data_str = val_data.hex()

            if _serial_in_string(serial, val_name) or \
               _serial_in_string(serial, data_str):
                result.hits.append(RegistryHit(
                    hive=_hive_name(hive_root),
                    key_path=full_path,
                    value_name=val_name,
                    match_context=data_str[:120],
                ))
                if delete_whole:
                    if backup_dir:
                        _backup_key(hive_root, full_path, backup_dir)
                    _delete_key_tree(hive_root, full_path)
                    result.deleted_keys.append(full_path)
                else:
                    try:
                        with winreg.OpenKey(
                            hive_root, full_path,
                            0, winreg.KEY_SET_VALUE
                        ) as wk:
                            winreg.DeleteValue(wk, val_name)
                        result.deleted_values.append(
                            f"{full_path}\\{val_name}"
                        )
                    except OSError as e:
                        result.errors.append(
                            f"Cannot delete value {full_path}\\{val_name}: {e}"
                        )
                break  # нашли в этом подключе — идём дальше


def _search_ntuser_online(
    serial: str,
    backup_dir: Optional[Path],
    result: RegistryResult,
) -> None:
    """Ищет серийник в NTUSER.DAT всех загруженных профилей."""
    profiles_key = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
    try:
        pk = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, profiles_key)
    except OSError:
        return

    with pk:
        profile_sids = _iter_subkeys(pk)

    for sid in profile_sids:
        for ntuser_path in NTUSER_KEY_PATHS:
            try:
                hku = winreg.OpenKey(
                    winreg.HKEY_USERS,
                    f"{sid}\\{ntuser_path}",
                    0, winreg.KEY_READ | winreg.KEY_ENUMERATE_SUB_KEYS
                )
            except OSError:
                continue

            with hku:
                mp2_subs = _iter_subkeys(hku)

            for mp in mp2_subs:
                if _serial_in_string(serial, mp):
                    full = f"{sid}\\{ntuser_path}\\{mp}"
                    result.hits.append(RegistryHit(
                        hive="NTUSER.DAT",
                        key_path=full,
                        value_name="",
                        match_context=f"MountPoints2 entry: {mp}",
                    ))
                    if backup_dir:
                        _backup_key(winreg.HKEY_USERS, full, backup_dir)
                    _delete_key_tree(winreg.HKEY_USERS, full)
                    result.deleted_keys.append(full)


# ─────────────────────────────────────────────
#  Офлайн-поиск (python-registry)
# ─────────────────────────────────────────────

def _search_offline_hive(
    hive_path: Path,
    serial: str,
    result: RegistryResult,
) -> None:
    """
    Парсит офлайн-файл хайва через python-registry.
    Только поиск (запись в офлайн-хайв не реализована —
    потребует ручной перезаписи файла).
    """
    if not OFFLINE_AVAILABLE:
        result.errors.append(
            "python-registry не установлен — офлайн-парсинг недоступен"
        )
        return

    if not hive_path.exists():
        return

    try:
        reg = LibRegistry.Registry(str(hive_path))
    except Exception as e:
        result.errors.append(f"Offline hive open error ({hive_path}): {e}")
        return

    def _walk(key):
        # проверяем имя ключа
        if _serial_in_string(serial, key.name()):
            result.hits.append(RegistryHit(
                hive=str(hive_path),
                key_path=key.path(),
                value_name="",
                match_context=f"[OFFLINE] key name: {key.name()}",
            ))

        # проверяем значения
        for val in key.values():
            data_str = ""
            try:
                raw = val.raw_data()
                if isinstance(raw, str):
                    data_str = raw
                elif isinstance(raw, bytes):
                    data_str = raw.decode("utf-16-le", errors="ignore")
                    if not data_str.strip():
                        data_str = raw.hex()
            except Exception:
                pass

            if _serial_in_string(serial, val.name()) or \
               _serial_in_string(serial, data_str):
                result.hits.append(RegistryHit(
                    hive=str(hive_path),
                    key_path=key.path(),
                    value_name=val.name(),
                    match_context=data_str[:120],
                ))

        # рекурсия по подключам
        for sub in key.subkeys():
            _walk(sub)

    _walk(reg.root())


# ─────────────────────────────────────────────
#  Утилита
# ─────────────────────────────────────────────

def _hive_name(hive_root: int) -> str:
    return {
        winreg.HKEY_LOCAL_MACHINE: "HKLM",
        winreg.HKEY_CURRENT_USER:  "HKCU",
        winreg.HKEY_USERS:         "HKU",
    }.get(hive_root, "UNKNOWN")


# ─────────────────────────────────────────────
#  Публичный API
# ─────────────────────────────────────────────

def run(
    serial: str,
    backup_dir: Optional[Path] = None,
    offline_hives: Optional[list[Path]] = None,
) -> RegistryResult:
    """
    Точка входа модуля.

    Args:
        serial:        Серийный номер USB-устройства для поиска.
        backup_dir:    Путь для .reg-бэкапов перед удалением.
        offline_hives: Список путей к офлайн-файлам хайвов
                       (для дополнительного анализа, без авто-удаления).

    Returns:
        RegistryResult с полным отчётом hits / deleted / errors.
    """
    result = RegistryResult()

    # — Онлайн: SYSTEM + SOFTWARE ключи —
    for hive_root, key_path, delete_whole in SYSTEM_KEYS + SOFTWARE_KEYS:
        _search_online_key(
            hive_root, key_path, serial,
            delete_whole, backup_dir, result
        )

    # — Онлайн: NTUSER.DAT (MountPoints2) —
    _search_ntuser_online(serial, backup_dir, result)

    # — Офлайн-хайвы (если переданы) —
    if offline_hives:
        for hive_path in offline_hives:
            _search_offline_hive(hive_path, serial, result)

    return result
