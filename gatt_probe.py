#!/usr/bin/env python3
"""
Ghost Wall — allowlist-gated GATT SELF-PROBE.

Hard safety constraint: this module only ever opens a BLE connection to an
address that is listed in trusted_devices.json. Every other address is refused
before any radio activity happens. There is no simulated / demo data path:
every value returned was read from the device, or is the literal "not exposed".
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("ghostwall.gatt_probe")

TRUSTED_FILE = Path(__file__).parent / "trusted_devices.json"

# Proximity safety guard. A device you own and are testing sits next to the
# laptop; a weaker signal is more likely a neighbour's device through a wall.
# Anything weaker than this is refused, for both probing and allowlisting.
PROXIMITY_DBM = -50
# An RSSI reading older than this is not evidence of where the device is now.
RSSI_MAX_AGE_S = 30.0

NOT_EXPOSED = "not exposed"
REFUSAL_REASON = "Address not in trusted_devices.json"
TOO_FAR_PROBE = f"Target too far (RSSI < {PROXIMITY_DBM}). Bring your own device within ~1m before probing."
TOO_FAR_TRUST = f"Target too far (RSSI < {PROXIMITY_DBM}). Bring your own device within ~1m before adding it to the allowlist."
NOT_VISIBLE = (
    f"Target not seen by the scanner in the last {int(RSSI_MAX_AGE_S)}s, so its distance cannot be checked. "
    "Wake your device and hold it within ~1m."
)
CONNECT_TIMEOUT = 10.0
READ_TIMEOUT = 5.0

# MAC (AA:BB:CC:DD:EE:FF) or CoreBluetooth peripheral UUID (macOS).
_ADDRESS_RE = re.compile(r"^[0-9A-Fa-f]{2}([:-][0-9A-Fa-f]{2}){5}$|^[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}$")

UUID_DEVICE_NAME = "00002a00-0000-1000-8000-00805f9b34fb"
UUID_MODEL_NUMBER = "00002a24-0000-1000-8000-00805f9b34fb"
UUID_MANUFACTURER = "00002a29-0000-1000-8000-00805f9b34fb"
UUID_FIRMWARE_REV = "00002a26-0000-1000-8000-00805f9b34fb"
UUID_SOFTWARE_REV = "00002a28-0000-1000-8000-00805f9b34fb"
UUID_BATTERY_LEVEL = "00002a19-0000-1000-8000-00805f9b34fb"

# The ONLY characteristics this module will ever read. Standard, read-only.
SAFE_READ_UUIDS: Dict[str, str] = {
    UUID_DEVICE_NAME: "device_name",
    UUID_MODEL_NUMBER: "model_number",
    UUID_MANUFACTURER: "manufacturer",
    UUID_FIRMWARE_REV: "firmware_revision",
    UUID_SOFTWARE_REV: "software_revision",
    UUID_BATTERY_LEVEL: "battery_level",
}

# Standard Bluetooth SIG GATT Services
GATT_SERVICE_NAMES: Dict[str, str] = {
    "00001800-0000-1000-8000-00805f9b34fb": "Generic Access",
    "00001801-0000-1000-8000-00805f9b34fb": "Generic Attribute",
    "0000180a-0000-1000-8000-00805f9b34fb": "Device Information",
    "0000180f-0000-1000-8000-00805f9b34fb": "Battery Service",
    "0000180d-0000-1000-8000-00805f9b34fb": "Heart Rate Service",
    "00001805-0000-1000-8000-00805f9b34fb": "Current Time Service",
    "00001812-0000-1000-8000-00805f9b34fb": "Human Interface Device",
    "0000d001-0000-1000-8000-00805f9b34fb": "Apple Continuity Service",
    "0000fd6f-0000-1000-8000-00805f9b34fb": "Exposure Notification",
    "0000fe9f-0000-1000-8000-00805f9b34fb": "Google Fast Pair",
}

# Standard Bluetooth SIG GATT Characteristics
GATT_CHAR_NAMES: Dict[str, str] = {
    "00002a00-0000-1000-8000-00805f9b34fb": "Device Name",
    "00002a01-0000-1000-8000-00805f9b34fb": "Appearance",
    "00002a04-0000-1000-8000-00805f9b34fb": "Peripheral Preferred Connection Parameters",
    "00002a05-0000-1000-8000-00805f9b34fb": "Service Changed",
    "00002a19-0000-1000-8000-00805f9b34fb": "Battery Level",
    "00002a24-0000-1000-8000-00805f9b34fb": "Model Number String",
    "00002a25-0000-1000-8000-00805f9b34fb": "Serial Number String",
    "00002a26-0000-1000-8000-00805f9b34fb": "Firmware Revision String",
    "00002a27-0000-1000-8000-00805f9b34fb": "Hardware Revision String",
    "00002a28-0000-1000-8000-00805f9b34fb": "Software Revision String",
    "00002a29-0000-1000-8000-00805f9b34fb": "Manufacturer Name String",
    "00002a50-0000-1000-8000-00805f9b34fb": "PnP ID",
}

# Apple Hardware Identifier Mapping Dictionary
APPLE_HARDWARE_MAP: Dict[str, str] = {
    # iPhones
    "iPhone10,1": "iPhone 8",
    "iPhone10,4": "iPhone 8",
    "iPhone10,2": "iPhone 8 Plus",
    "iPhone10,5": "iPhone 8 Plus",
    "iPhone10,3": "iPhone X",
    "iPhone10,6": "iPhone X",
    "iPhone11,2": "iPhone XS",
    "iPhone11,4": "iPhone XS Max",
    "iPhone11,6": "iPhone XS Max",
    "iPhone11,8": "iPhone XR",
    "iPhone12,1": "iPhone 11",
    "iPhone12,3": "iPhone 11 Pro",
    "iPhone12,5": "iPhone 11 Pro Max",
    "iPhone12,8": "iPhone SE (2nd gen)",
    "iPhone13,1": "iPhone 12 mini",
    "iPhone13,2": "iPhone 12",
    "iPhone13,3": "iPhone 12 Pro",
    "iPhone13,4": "iPhone 12 Pro Max",
    "iPhone14,2": "iPhone 13 Pro",
    "iPhone14,3": "iPhone 13 Pro Max",
    "iPhone14,4": "iPhone 13 mini",
    "iPhone14,5": "iPhone 13",
    "iPhone14,6": "iPhone SE (3rd gen)",
    "iPhone14,7": "iPhone 14",
    "iPhone14,8": "iPhone 14 Plus",
    "iPhone15,2": "iPhone 14 Pro",
    "iPhone15,3": "iPhone 14 Pro Max",
    "iPhone15,4": "iPhone 15",
    "iPhone15,5": "iPhone 15 Plus",
    "iPhone16,1": "iPhone 15 Pro",
    "iPhone16,2": "iPhone 15 Pro Max",
    "iPhone17,1": "iPhone 16 Pro",
    "iPhone17,2": "iPhone 16 Pro Max",
    "iPhone17,3": "iPhone 16",
    "iPhone17,4": "iPhone 16 Plus",
    "iPhone18,1": "iPhone 17 Pro",
    "iPhone18,2": "iPhone 17 Pro Max",

    # iPads
    "iPad11,6": "iPad (8th gen)",
    "iPad11,7": "iPad (8th gen)",
    "iPad12,1": "iPad (9th gen)",
    "iPad12,2": "iPad (9th gen)",
    "iPad13,18": "iPad (10th gen)",
    "iPad13,19": "iPad (10th gen)",
    "iPad13,1": "iPad Air (4th gen)",
    "iPad13,2": "iPad Air (4th gen)",
    "iPad13,16": "iPad Air (5th gen)",
    "iPad13,17": "iPad Air (5th gen)",
    "iPad14,8": "iPad Air 11-inch (M2)",
    "iPad14,9": "iPad Air 11-inch (M2)",
    "iPad14,10": "iPad Air 13-inch (M2)",
    "iPad14,11": "iPad Air 13-inch (M2)",
    "iPad13,4": "iPad Pro 11-inch (3rd gen / M1)",
    "iPad13,8": "iPad Pro 12.9-inch (5th gen / M1)",
    "iPad14,3": "iPad Pro 11-inch (4th gen / M2)",
    "iPad14,6": "iPad Pro 12.9-inch (6th gen / M2)",
    "iPad16,3": "iPad Pro 11-inch (M4)",
    "iPad16,4": "iPad Pro 11-inch (M4)",
    "iPad16,5": "iPad Pro 13-inch (M4)",
    "iPad16,6": "iPad Pro 13-inch (M4)",
    "iPad14,1": "iPad mini (6th gen)",
    "iPad14,2": "iPad mini (6th gen)",
    "iPad16,1": "iPad mini (A17 Pro)",
    "iPad16,2": "iPad mini (A17 Pro)",

    # Macs
    "MacBookAir9,1": "MacBook Air (Intel 2020)",
    "MacBookAir10,1": "MacBook Air (M1, 2020)",
    "Mac14,2": "MacBook Air 13-inch (M2, 2022)",
    "Mac14,15": "MacBook Air 15-inch (M2, 2023)",
    "Mac15,2": "MacBook Air 13-inch (M3, 2024)",
    "Mac15,13": "MacBook Air 15-inch (M3, 2024)",
    "MacBookPro17,1": "MacBook Pro 13-inch (M1, 2020)",
    "MacBookPro18,1": "MacBook Pro 16-inch (M1 Pro, 2021)",
    "MacBookPro18,2": "MacBook Pro 16-inch (M1 Max, 2021)",
    "MacBookPro18,3": "MacBook Pro 14-inch (M1 Pro, 2021)",
    "MacBookPro18,4": "MacBook Pro 14-inch (M1 Max, 2021)",
    "Mac14,7": "MacBook Pro 13-inch (M2, 2022)",
    "Mac14,9": "MacBook Pro 14-inch (M2 Pro/Max, 2023)",
    "Mac14,10": "MacBook Pro 16-inch (M2 Pro/Max, 2023)",
    "Mac15,3": "MacBook Pro 14-inch (M3, 2023)",
    "Mac15,6": "MacBook Pro 14-inch (M3 Pro, 2023)",
    "Mac15,7": "MacBook Pro 16-inch (M3 Pro, 2023)",
    "Mac15,8": "MacBook Pro 14-inch (M3 Max, 2023)",
    "Mac15,9": "MacBook Pro 16-inch (M3 Max, 2023)",
    "Mac16,1": "MacBook Pro 14-inch (M4, 2024)",
    "Mac16,5": "MacBook Pro 14-inch (M4 Pro, 2024)",
    "Mac16,6": "MacBook Pro 16-inch (M4 Pro, 2024)",
    "Mac16,7": "MacBook Pro 14-inch (M4 Max, 2024)",
    "Mac16,8": "MacBook Pro 16-inch (M4 Max, 2024)",
    "Macmini9,1": "Mac mini (M1, 2020)",
    "Mac14,3": "Mac mini (M2, 2023)",
    "Mac14,12": "Mac mini (M2 Pro, 2023)",
    "Mac16,10": "Mac mini (M4, 2024)",
    "Mac16,11": "Mac mini (M4 Pro, 2024)",
    "Mac14,8": "Mac Studio (M2 Max, 2023)",
    "Mac14,13": "Mac Studio (M2 Ultra, 2023)",
    "Mac14,14": "Mac Pro (M2 Ultra, 2023)",
    "Mac15,4": "iMac 24-inch (M3, 2-port)",
    "Mac15,5": "iMac 24-inch (M3, 4-port)",
    "Mac16,2": "iMac 24-inch (M4, 2-port)",
    "Mac16,3": "iMac 24-inch (M4, 4-port)",

    # Apple Watches
    "Watch5,1": "Apple Watch Series 5 (40mm)",
    "Watch5,2": "Apple Watch Series 5 (44mm)",
    "Watch5,9": "Apple Watch SE (40mm)",
    "Watch5,10": "Apple Watch SE (44mm)",
    "Watch6,1": "Apple Watch Series 6 (40mm)",
    "Watch6,2": "Apple Watch Series 6 (44mm)",
    "Watch6,6": "Apple Watch Series 7 (41mm)",
    "Watch6,7": "Apple Watch Series 7 (45mm)",
    "Watch6,14": "Apple Watch Series 8 (41mm)",
    "Watch6,15": "Apple Watch Series 8 (45mm)",
    "Watch6,16": "Apple Watch Ultra",
    "Watch6,17": "Apple Watch Ultra",
    "Watch7,1": "Apple Watch Series 9 (41mm)",
    "Watch7,2": "Apple Watch Series 9 (45mm)",
    "Watch7,5": "Apple Watch Ultra 2",
    "Watch7,8": "Apple Watch Series 10 (42mm)",
    "Watch7,9": "Apple Watch Series 10 (46mm)",

    # AirPods & Audio
    "AirPods1,1": "AirPods (1st gen)",
    "AirPods2,1": "AirPods (2nd gen)",
    "Audio2,1": "AirPods (3rd gen)",
    "iProd8,1": "AirPods Pro (1st gen)",
    "AirPodsPro1,2": "AirPods Pro (2nd gen)",
    "AirPodsPro2,1": "AirPods Pro (2nd gen, USB-C)",
    "iProd8,6": "AirPods Max",
}

# One probe at a time: the scanner is paused for the duration of a connection.
_probe_lock = asyncio.Lock()


# ============================================================================
# Allowlist (trusted_devices.json)
# ============================================================================

def _norm(address: Any) -> str:
    return address.strip().lower() if isinstance(address, str) else ""


def load_trusted() -> List[Dict[str, str]]:
    """Returns the allowlist. Missing or unreadable file == empty list (fail closed)."""
    try:
        raw = json.loads(TRUSTED_FILE.read_text(encoding="utf-8"))
    except FileNotFoundError:
        _save_trusted([])
        return []
    except (OSError, ValueError) as e:
        logger.error(f"trusted_devices.json unreadable ({e}); treating allowlist as empty")
        return []
    if not isinstance(raw, list):
        logger.error("trusted_devices.json is not a JSON list; treating allowlist as empty")
        return []
    devices = []
    for item in raw:
        if isinstance(item, dict) and isinstance(item.get("address"), str) and item["address"].strip():
            devices.append({"address": item["address"].strip(), "label": str(item.get("label") or "")})
    return devices


def _save_trusted(devices: List[Dict[str, str]]) -> None:
    fd, tmp = tempfile.mkstemp(dir=str(TRUSTED_FILE.parent), prefix=".trusted_", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(devices, f, indent=2, ensure_ascii=False)
            f.write("\n")
        os.replace(tmp, TRUSTED_FILE)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def is_trusted(address: Any) -> bool:
    """True only if address is in trusted_devices.json (case-insensitive exact match)."""
    needle = _norm(address)
    if not needle:
        return False
    return any(_norm(d["address"]) == needle for d in load_trusted())


def proximity_refusal(rssi: Optional[int], too_far_reason: str = TOO_FAR_PROBE) -> Optional[str]:
    """
    Proximity guard. `rssi` is the target's most recent RSSI in dBm, or None if
    the scanner has no fresh reading. Returns a refusal reason, or None if the
    target is close enough. An unknown distance is refused, never assumed near.
    """
    if rssi is None or isinstance(rssi, bool) or not isinstance(rssi, (int, float)):
        return NOT_VISIBLE
    if rssi < PROXIMITY_DBM:
        return too_far_reason
    return None


class ProximityError(ValueError):
    """Raised when trust_device is refused by the proximity guard."""


def trust_device(address: Any, label: Any = "", rssi: Optional[int] = None) -> List[Dict[str, str]]:
    """
    Adds (or relabels) an address in the allowlist. `rssi` is the device's most
    recent RSSI; weaker than PROXIMITY_DBM (or unknown) is refused with
    ProximityError. Raises ValueError on a bad address.
    """
    addr = address.strip() if isinstance(address, str) else ""
    if not _ADDRESS_RE.match(addr):
        raise ValueError("Not a valid BLE address (expected a MAC or CoreBluetooth UUID)")
    refusal = proximity_refusal(rssi, TOO_FAR_TRUST)
    if refusal:
        logger.warning(f"Allowlist: REFUSED to trust {addr} (RSSI {rssi}): {refusal}")
        raise ProximityError(refusal)
    label = (str(label).strip() if label else "")[:64] or addr
    devices = load_trusted()
    for d in devices:
        if _norm(d["address"]) == _norm(addr):
            d["label"] = label
            break
    else:
        devices.append({"address": addr, "label": label})
    _save_trusted(devices)
    logger.info(f"Allowlist: trusted {addr} ({label})")
    return devices


def untrust_device(address: Any) -> List[Dict[str, str]]:
    """Removes an address from the allowlist."""
    needle = _norm(address)
    devices = [d for d in load_trusted() if _norm(d["address"]) != needle]
    _save_trusted(devices)
    logger.info(f"Allowlist: removed {address}")
    return devices


# ============================================================================
# Gated GATT read
# ============================================================================

def marketing_name(model_number: str) -> str:
    """Apple model identifier -> marketing name; anything else is returned unchanged."""
    return APPLE_HARDWARE_MAP.get(model_number, model_number)


async def _safe_read(client: Any, char: Any, uuid: str) -> Any:
    """Reads one allowlisted characteristic. Any failure or empty value -> "not exposed"."""
    if "read" not in [p.lower() for p in char.properties]:
        return NOT_EXPOSED
    try:
        raw = bytes(await asyncio.wait_for(client.read_gatt_char(char), timeout=READ_TIMEOUT))
    except Exception as e:  # auth / encryption / timeout / disconnect
        logger.info(f"Read of {uuid} not permitted: {e!r}")
        return NOT_EXPOSED
    if not raw:
        return NOT_EXPOSED
    if uuid == UUID_BATTERY_LEVEL:
        return raw[0] if raw[0] <= 100 else NOT_EXPOSED
    try:
        text = raw.decode("utf-8").strip("\x00").strip()
    except UnicodeDecodeError:
        text = raw.hex()
    return text or NOT_EXPOSED


async def _read_device(client: Any) -> Dict[str, Any]:
    readable: Dict[str, Any] = {key: NOT_EXPOSED for key in SAFE_READ_UUIDS.values()}
    services: List[Dict[str, Any]] = []

    for service in client.services:
        s_uuid = service.uuid.lower()
        chars = []
        for char in service.characteristics:
            c_uuid = char.uuid.lower()
            entry: Dict[str, Any] = {
                "uuid": c_uuid,
                "name": GATT_CHAR_NAMES.get(c_uuid, ""),
                "properties": [p.lower() for p in char.properties],
                # None == never attempted (outside the safe read list)
                "value": None,
            }
            key = SAFE_READ_UUIDS.get(c_uuid)
            if key:
                value = await _safe_read(client, char, c_uuid)
                entry["value"] = f"{value}%" if key == "battery_level" and value != NOT_EXPOSED else value
                if readable[key] == NOT_EXPOSED:
                    readable[key] = value
            chars.append(entry)
        services.append({
            "uuid": s_uuid,
            "name": GATT_SERVICE_NAMES.get(s_uuid, ""),
            "characteristics": chars,
        })

    model_number = readable["model_number"]
    model = marketing_name(model_number) if model_number != NOT_EXPOSED else NOT_EXPOSED
    return {"services": services, "readable_values": readable, "model": model}


async def probe(address: Any, scanner: Optional[Any] = None, rssi: Optional[int] = None) -> Dict[str, Any]:
    """
    Handles {"action": "gatt_probe", "address": ...}.

    is_trusted() is checked before anything else; an address that is not in
    trusted_devices.json is refused without touching the radio. `scanner` is
    the server's running BleakScanner: it is paused while connected (CoreBluetooth
    drops connection attempts made during an active scan) and always resumed.

    `rssi` is the target's most recent RSSI (None if the scanner has no fresh
    reading). Weaker than PROXIMITY_DBM, or unknown, is refused without connecting.
    """
    addr = address.strip() if isinstance(address, str) else ""

    if not is_trusted(addr):
        logger.warning(f"GATT probe REFUSED for {addr or '<empty>'}: {REFUSAL_REASON}")
        return {"type": "probe_result", "status": "refused", "address": addr, "reason": REFUSAL_REASON}

    refusal = proximity_refusal(rssi)
    if refusal:
        logger.warning(f"GATT probe REFUSED for {addr} (RSSI {rssi}): {refusal}")
        return {"type": "probe_result", "status": "refused", "address": addr, "reason": refusal}

    from bleak import BleakClient

    async with _probe_lock:
        paused = False
        try:
            if scanner is not None:
                try:
                    await scanner.stop()
                    paused = True
                except Exception as e:
                    logger.warning(f"Could not pause BleakScanner before probe: {e!r}")

            logger.info(f"Self-probe: connecting to trusted device {addr} (timeout {CONNECT_TIMEOUT}s)")
            client = BleakClient(addr, timeout=CONNECT_TIMEOUT)
            try:
                await client.connect()
                data = await _read_device(client)
            finally:
                try:
                    await client.disconnect()
                except Exception:
                    pass
        except Exception as e:
            logger.warning(f"Self-probe of {addr} failed: {e!r}")
            return {
                "type": "probe_result",
                "status": "error",
                "address": addr,
                "error": str(e) or type(e).__name__,
            }
        finally:
            if paused:
                try:
                    await scanner.start()
                except Exception as e:
                    logger.error(f"Failed to resume BleakScanner after probe: {e!r}")

    logger.info(f"Self-probe of {addr} complete: {len(data['services'])} services, model={data['model']}")
    return {"type": "probe_result", "status": "success", "address": addr, "data": data}
