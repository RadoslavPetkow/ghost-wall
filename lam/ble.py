"""BLE източник: пасивно слуша advertisement пакети през bleak."""
from __future__ import annotations

import asyncio
import hashlib

from .core import Registry, Sighting

BASE = "-0000-1000-8000-00805f9b34fb"


def _u16(x: int) -> str:
    return f"0000{x:04x}{BASE}"


VENDORS = {
    0x004C: "Apple", 0x0006: "Microsoft", 0x0075: "Samsung", 0x00E0: "Google",
    0x038F: "Xiaomi", 0x027D: "Huawei", 0x0087: "Garmin", 0x009E: "Bose",
    0x012D: "Sony", 0x0059: "Nordic", 0x0157: "Huami/Amazfit", 0x00D2: "Dialog",
}

# Apple "continuity" типове (първи байт след company ID 0x004C)
APPLE_TYPES = {
    0x02: "iBeacon", 0x05: "AirDrop", 0x07: "AirPods/слушалки", 0x09: "AirPlay", 0x0A: "AirPlay източник",
    0x0C: "Handoff", 0x0F: "Nearby Action", 0x10: "iPhone/iPad/Mac (Nearby)",
    0x12: "Find My",
}

# Service UUID-та, които издават тракер (евристика, не доказателство)
TRACKER_UUIDS = {
    _u16(0xFCB2): "Тракер (DULT стандарт)",
    _u16(0xFEED): "Tile тракер",
    _u16(0xFEEC): "Tile тракер",
    _u16(0xFD5A): "Samsung SmartTag",
    _u16(0xFD59): "Samsung SmartTag",
}
GOOGLE_EDDYSTONE = _u16(0xFEAA)  # Find My Device мрежата: frame type 0x40/0x41


# Битове 4-5 от статус байта подсказват вида (по AirGuard; непотвърдена евристика)
FM_TYPES = {0b00: "аксесоар", 0b01: "AirTag", 0b10: "Apple устройство", 0b11: "AirPods"}


def find_my(payload: bytes):
    """Find My (0x12) кадър -> (описание, отделен_от_собственика, белег за отпечатък).

    Дължина 0x19 = устройството е далеч от собственика си и излъчва публичен ключ
    (само това състояние може да те следи). Къса дължина = собственикът е до него.
    """
    length = payload[1] if len(payload) > 1 else 0
    status = payload[2] if len(payload) > 2 else 0
    separated = length >= 0x19
    if not separated:  # къс пакет: статус байтът не носи вида
        return "Find My · при собственика", False, f"fm{length:02x}"
    hint = FM_TYPES[(status >> 4) & 0b11]
    return (f"Find My · {hint}? · далеч от собственика [{status:02x}]", True,
            f"fm{length:02x}{status & 0x30:02x}")


def classify(name, manufacturer_data, service_uuids, service_data):
    """Връща (vendor, kind, tracker, fingerprint)."""
    vendor, kind, tracker, fm = "", "", False, ""

    for cid, payload in manufacturer_data.items():
        vendor = VENDORS.get(cid, vendor or f"0x{cid:04X}")
        if cid == 0x004C and payload:
            kind = APPLE_TYPES.get(payload[0], f"Apple 0x{payload[0]:02X}")
            if payload[0] == 0x12:
                kind, tracker, fm = find_my(payload)

    uuids = {u.lower() for u in service_uuids} | {u.lower() for u in service_data}
    for u in uuids:
        if u in TRACKER_UUIDS:
            kind, tracker = TRACKER_UUIDS[u], True
    fmdn = next((v for k, v in service_data.items() if k.lower() == GOOGLE_EDDYSTONE), b"")
    if fmdn and fmdn[0] in (0x40, 0x41):
        vendor, kind, tracker = vendor or "Google", "Google Find My Device тракер", True

    # Отпечатък: кои полета присъстват (не съдържанието, което се върти)
    parts = sorted(f"m{cid:04x}:{p[:1].hex()}" for cid, p in manufacturer_data.items())
    parts += sorted(f"s{u[4:8]}" for u in uuids)
    if fm:
        parts.append(fm)
    fp = hashlib.sha1("|".join(parts).encode()).hexdigest()[:8] if parts else ""
    return vendor, kind, tracker, fp


async def run_ble(registry: Registry, stop: asyncio.Event) -> None:
    from bleak import BleakScanner

    def on_adv(device, adv):
        vendor, kind, tracker, fp = classify(
            adv.local_name or device.name or "",
            adv.manufacturer_data, adv.service_uuids, adv.service_data,
        )
        registry.observe(Sighting(
            source="ble", key=device.address, rssi=adv.rssi,
            name=adv.local_name or device.name or "",
            vendor=vendor, kind=kind, tracker=tracker, fingerprint=fp,
        ))

    async with BleakScanner(detection_callback=on_adv):
        await stop.wait()
