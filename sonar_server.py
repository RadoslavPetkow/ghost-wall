#!/usr/bin/env python3
"""
Ghost Wall — Tactical BLE Sonar & Continuity Profiler
Backend server: BleakScanner + Apple Continuity DPI + WebSocket (8765) + HTTP (8080)
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import os
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

from aiohttp import web

import gatt_probe
import websockets
try:
    from websockets.asyncio.server import ServerConnection as WsConn
except ImportError:
    try:
        from websockets.server import WebSocketServerProtocol as WsConn
    except ImportError:
        WsConn = Any  # type: ignore

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("ghostwall")

# Base UUID for Bluetooth standard 16-bit UUID expansion
BASE_UUID_SUFFIX = "-0000-1000-8000-00805f9b34fb"


def u16_to_uuid(x: int) -> str:
    return f"0000{x:04x}{BASE_UUID_SUFFIX}".lower()


# Vendor Company Identifiers (Bluetooth SIG)
VENDORS: Dict[int, str] = {
    0x004C: "Apple",
    0x0006: "Microsoft",
    0x0075: "Samsung",
    0x00E0: "Google",
    0x038F: "Xiaomi",
    0x027D: "Huawei",
    0x0087: "Garmin",
    0x009E: "Bose",
    0x012D: "Sony",
    0x0059: "Nordic Semi",
    0x0157: "Huami / Amazfit",
    0x00D2: "Dialog Semi",
    0x0047: "LG Electronics",
    0x01DA: "Logitech",
    0x000A: "Qualcomm",
    0x0382: "Anker / Soundcore",
    0x0822: "OnePlus",
    0x0499: "Ruuvi",
    0x0171: "Amazon",
    0x0001: "Nokia",
}

# Apple Continuity Types (first byte of Apple manufacturer data)
APPLE_TYPES: Dict[int, str] = {
    0x02: "iBeacon",
    0x03: "AirPrint",
    0x05: "AirDrop",
    0x06: "HomeKit",
    0x07: "AirPods / Proximity Pairing",
    0x08: "Hey Siri",
    0x09: "AirPlay Target",
    0x0A: "AirPlay Source",
    0x0B: "Magic Switch",
    0x0C: "Handoff",
    0x0D: "Tethering Source",
    0x0E: "Tethering Target",
    0x0F: "Nearby Action",
    0x10: "Nearby Info (iPhone/iPad/Mac)",
    0x12: "Find My Tracker",
}

# Tracker Service UUIDs
TRACKER_UUIDS: Dict[str, str] = {
    u16_to_uuid(0xFCB2): "Tracker (DULT Standard)",
    u16_to_uuid(0xFEED): "Tile Tracker",
    u16_to_uuid(0xFEEC): "Tile Tracker",
    u16_to_uuid(0xFD5A): "Samsung SmartTag",
    u16_to_uuid(0xFD59): "Samsung SmartTag",
}
GOOGLE_EDDYSTONE = u16_to_uuid(0xFEAA)

FM_TYPES = {
    0b00: "Accessory",
    0b01: "AirTag",
    0b10: "Apple Device",
    0b11: "AirPods",
}


# ============================================================================
# Apple Continuity Deep Packet Inspection (0x004C)
# ============================================================================

def parse_apple_nearby_info(val: bytes, raw: bytes) -> Dict[str, Any]:
    """
    0x10 Nearby Info (iPhone/iPad/Mac):
    Parses status_flags (byte 0) and action_code (byte 1).
    - action_code & 0x01 -> Screen UNLOCKED / Active vs LOCKED
    - active audio (0x20)
    - connected Watch (0x40)
    - Continuity Auth Tag (3 bytes, bytes 2..5 of payload)
    """
    # Depending on whether val has length header or raw offset
    status_flags = 0
    action_code = 0
    auth_tag = ""
    
    if len(val) >= 2:
        status_flags = val[0]
        action_code = val[1]
        if len(val) >= 5:
            auth_tag = val[2:5].hex()
    elif len(raw) >= 4 and raw[0] == 0x10:
        # Check standard TLV [10, len, status, action, auth_tag...]
        status_flags = raw[2]
        action_code = raw[3]
        if len(raw) >= 7:
            auth_tag = raw[4:7].hex()
    elif len(raw) >= 3 and raw[0] == 0x10:
        status_flags = raw[1]
        action_code = raw[2]

    screen_unlocked = bool(action_code & 0x01)
    active_audio = bool((action_code & 0x20) or (status_flags & 0x20))
    watch_connected = bool((action_code & 0x40) or (status_flags & 0x40))

    return {
        "status_flags": status_flags,
        "action_code": action_code,
        "status_flags_hex": f"0x{status_flags:02X}",
        "action_code_hex": f"0x{action_code:02X}",
        "screen_unlocked": screen_unlocked,
        "active_audio": active_audio,
        "watch_connected": watch_connected,
        "auth_tag": auth_tag,
    }


def parse_apple_proximity_pairing(val: bytes, raw: bytes) -> Dict[str, Any]:
    """
    0x07 Proximity Pairing (AirPods / Beats):
    Detects open case and extracts raw battery nibbles if available.
    """
    battery = None
    b_data = val if len(val) >= 6 else (raw[2:] if len(raw) >= 8 else raw)

    if len(b_data) >= 7:
        # Bytes 5 & 6 often hold battery nibbles
        b1 = b_data[5]
        b2 = b_data[6]
        left_n = (b1 >> 4) & 0x0F
        right_n = b1 & 0x0F
        case_n = (b2 >> 4) & 0x0F
        charging_case = bool(b2 & 0x04)
        charging_right = bool(b2 & 0x02)
        charging_left = bool(b2 & 0x01)

        def fmt_pct(nibble: int) -> str:
            if nibble <= 10:
                return f"{nibble * 10}%"
            elif nibble == 15:
                return "Disconnected"
            return f"Nibble 0x{nibble:X}"

        battery = {
            "left": fmt_pct(left_n),
            "right": fmt_pct(right_n),
            "case": fmt_pct(case_n),
            "left_raw": left_n,
            "right_raw": right_n,
            "case_raw": case_n,
            "charging_left": charging_left,
            "charging_right": charging_right,
            "charging_case": charging_case,
            "raw_hex": b_data[:8].hex(),
        }

    return {
        "airpods_open": True,
        "battery": battery,
    }


def parse_apple_find_my(val: bytes, raw: bytes) -> Dict[str, Any]:
    """
    0x12 Find My Tracker:
    Detects separated AirTags vs near owner.
    Length >= 0x19 (25 bytes) = separated from owner, broadcasting rotating public key.
    """
    # Check length byte in raw
    length = raw[1] if len(raw) > 1 else len(val)
    status = raw[2] if len(raw) > 2 else (val[0] if len(val) > 0 else 0)
    separated = length >= 0x19 or len(raw) >= 25 or len(val) >= 23
    hint_idx = (status >> 4) & 0b11
    hint = FM_TYPES.get(hint_idx, "Accessory")

    return {
        "is_find_my": True,
        "separated": separated,
        "status": status,
        "status_hex": f"0x{status:02X}",
        "hint": hint,
        "length": length,
    }


def parse_apple_continuity(raw: bytes) -> Dict[str, Any]:
    """
    Complete Apple Continuity Deep Packet Inspection.
    Handles multiple chained TLVs or standalone payloads.
    """
    res: Dict[str, Any] = {
        "is_apple": True,
        "types": [],
        "screen_unlocked": False,
        "screen_state_known": False,
        "active_audio": False,
        "watch_connected": False,
        "airpods_open": False,
        "battery": None,
        "handoff_active": False,
        "find_my_separated": None,
        "find_my_hint": "",
        "status_flags": 0,
        "action_code": 0,
        "auth_tag": "",
        "raw_hex": raw.hex() if raw else "",
        "state_label": "IDLE",
        "details": [],
    }

    if not raw:
        return res

    # Iterate through Apple Continuity TLVs: [Type, Len, Value...]
    i = 0
    tlvs = []
    while i < len(raw):
        t = raw[i]
        res["types"].append(t)
        if i + 1 < len(raw):
            l = raw[i + 1]
            val = raw[i + 2 : min(len(raw), i + 2 + l)]
            tlvs.append((t, l, val, raw[i:]))
            i += max(2, 2 + l)
        else:
            tlvs.append((t, 0, raw[i:], raw[i:]))
            break

    for t, l, val, sub_raw in tlvs:
        if t == 0x10:  # Nearby Info
            ni = parse_apple_nearby_info(val, sub_raw)
            res["screen_state_known"] = True
            res["screen_unlocked"] = ni["screen_unlocked"]
            res["active_audio"] = ni["active_audio"]
            res["watch_connected"] = ni["watch_connected"]
            res["status_flags"] = ni["status_flags"]
            res["action_code"] = ni["action_code"]
            if ni.get("auth_tag"):
                res["auth_tag"] = ni["auth_tag"]
            if ni["screen_unlocked"]:
                res["details"].append("Screen UNLOCKED / Active")
            else:
                res["details"].append("Screen Locked")
            if ni["active_audio"]:
                res["details"].append("Audio Active")
            if ni["watch_connected"]:
                res["details"].append("Apple Watch")

        elif t == 0x07:  # Proximity Pairing (AirPods/Beats)
            pp = parse_apple_proximity_pairing(val, sub_raw)
            res["airpods_open"] = True
            if pp.get("battery"):
                res["battery"] = pp["battery"]
                res["details"].append(f"AirPods Case Open ({pp['battery'].get('case', '')})")
            else:
                res["details"].append("AirPods Case Open")

        elif t == 0x0C:  # Handoff
            res["handoff_active"] = True
            res["details"].append("Handoff (App Switch / Clipboard)")

        elif t == 0x12:  # Find My
            fm = parse_apple_find_my(val, sub_raw)
            res["find_my_separated"] = fm["separated"]
            res["find_my_hint"] = fm["hint"]
            res["status_flags"] = fm["status"]
            desc = f"Find My · {fm['hint']} · {'SEPARATED from owner' if fm['separated'] else 'Near owner'}"
            res["details"].append(desc)

        elif t in APPLE_TYPES:
            res["details"].append(APPLE_TYPES[t])

    # Determine primary state label
    if res["screen_unlocked"]:
        res["state_label"] = "SCREEN UNLOCKED"
    elif res["handoff_active"]:
        res["state_label"] = "HANDOFF ACTIVE"
    elif res["airpods_open"]:
        res["state_label"] = "AIRPODS OPEN"
    elif res["find_my_separated"] is True:
        res["state_label"] = "AIRTAG SEPARATED"
    elif res["find_my_separated"] is False:
        res["state_label"] = "FIND MY (OWNER)"
    elif res["screen_state_known"]:
        res["state_label"] = "SCREEN LOCKED"
    else:
        res["state_label"] = "IDLE"

    return res


# ============================================================================
# Classification & Stable Fingerprinting (Entity Resolution)
# ============================================================================

def classify_packet(
    name: str,
    manufacturer_data: Dict[int, bytes],
    service_uuids: List[str],
    service_data: Dict[str, bytes],
    address: str,
) -> tuple[str, str, bool, str, Dict[str, Any]]:
    """
    Classifies a BLE advertisement into (vendor, kind, tracker, signature, apple_dpi).
    The signature hashes the advertisement STRUCTURE only. Every device of the same
    model produces the same one, so it identifies a class of device, never one device.
    """
    vendor = ""
    kind = ""
    tracker = False
    apple_dpi: Dict[str, Any] = {}
    fm_marker = ""

    # Check manufacturer data
    for cid, payload in manufacturer_data.items():
        vendor = VENDORS.get(cid, vendor or f"0x{cid:04X}")
        if cid == 0x004C and payload:
            apple_dpi = parse_apple_continuity(payload)
            primary_type = payload[0]
            kind = APPLE_TYPES.get(primary_type, f"Apple 0x{primary_type:02X}")
            if primary_type == 0x12:
                tracker = True
                length = payload[1] if len(payload) > 1 else 0
                status = payload[2] if len(payload) > 2 else 0
                separated = length >= 0x19
                hint = FM_TYPES.get((status >> 4) & 0b11, "Accessory")
                kind = f"Find My · {hint} ({'Separated' if separated else 'Near owner'})"
                fm_marker = f"fm{length:02x}{status & 0x30:02x}"

    # Check Service UUIDs
    all_uuids = {u.lower() for u in service_uuids} | {u.lower() for u in service_data}
    for u in all_uuids:
        if u in TRACKER_UUIDS:
            kind, tracker = TRACKER_UUIDS[u], True

    # Check Google Eddystone / Find My Device
    fmdn = next((v for k, v in service_data.items() if k.lower() == GOOGLE_EDDYSTONE), b"")
    if fmdn and fmdn[0] in (0x40, 0x41):
        vendor = vendor or "Google"
        kind = "Google Find My Device Tracker"
        tracker = True

    # Fallback vendor / kind
    if not vendor:
        if name:
            vendor = "Unknown (Named)"
        else:
            vendor = "Unknown"
    if not kind:
        kind = "BLE Peripheral"

    # Advertisement-structure signature (shared by all same-model devices; NOT an identity)
    parts = []
    for cid, p in sorted(manufacturer_data.items()):
        # Include company id, primary type, and payload length (structural invariants)
        type_hex = p[:1].hex() if p else "00"
        parts.append(f"m{cid:04x}:t{type_hex}:l{len(p):02x}")
    for u in sorted(all_uuids):
        # 16-bit short UUID if available
        if len(u) >= 8:
            parts.append(f"s{u[4:8]}")
        else:
            parts.append(f"s{u}")
    if fm_marker:
        parts.append(fm_marker)

    if parts:
        fp = hashlib.sha1("|".join(parts).encode()).hexdigest()[:8]
    else:
        # Non-advertising or empty-payload fixed device: key by address hash
        clean_addr = address.replace(":", "").replace("-", "").lower()
        fp = f"mac_{clean_addr[-6:]}"

    return vendor, kind, tracker, fp, apple_dpi


# ============================================================================
# Entity and Registry Model
# ============================================================================

@dataclass
class ActivityEvent:
    id: str
    ts: float
    time_str: str
    fp: str
    name: str
    vendor: str
    kind: str
    action: str  # "screen_unlocked" | "screen_locked" | "airpods_open" | "handoff" | "proximity" | "mac_rotation" | "airtag"
    description: str
    rssi: int
    level: str  # "info" | "warn" | "alert"
    entity: Optional[Dict[str, Any]] = None


@dataclass
class Entity:
    fp: str
    addresses: List[str]
    mac_count: int
    current_address: str
    name: str
    vendor: str
    kind: str
    tracker: bool
    rssi: int
    best_rssi: int
    rssi_ema: float
    rssi_history: List[int] = field(default_factory=list)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    count: int = 1
    continuity: Dict[str, Any] = field(default_factory=dict)
    state_label: str = "IDLE"
    angle: float = 0.0
    is_watched: bool = False
    custom_alias: str = ""
    raw_hex: str = ""
    hardware_model: str = ""
    raw_model: str = ""
    firmware: str = ""
    battery_level: Optional[int] = None
    device_name: str = ""
    auth_tag: str = ""
    # Advertisement-structure hash. Shared by every same-model device, so it is not an identity.
    signature: str = ""
    # True once probes returned conflicting model numbers under this signature / entity.
    ambiguous: bool = False
    models_seen: List[Dict[str, str]] = field(default_factory=list)
    # Addresses whose model number was actually read by a probe.
    confirmed_addresses: List[str] = field(default_factory=list)

    # Internal state tracking for diffing
    prev_screen_unlocked: bool = False
    prev_airpods_open: bool = False
    prev_handoff: bool = False
    prev_rssi: int = -999
    airtag_warned: bool = False

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # Remove private fields
        for k in list(d.keys()):
            if k.startswith("prev_"):
                del d[k]
        d["age_seconds"] = round(self.last_seen - self.first_seen, 1)
        d["idle_seconds"] = round(time.time() - self.last_seen, 1)
        return d


class SonarRegistry:
    def __init__(
        self,
        proximity_threshold: int = -65,
        expire_seconds: float = 120.0,
        voice_alerts: bool = True,
        on_event: Optional[Callable[[ActivityEvent], Any]] = None,
    ):
        self.entities: Dict[str, Entity] = {}
        self.all_seen_addresses: Set[str] = set()
        self.proximity_threshold = proximity_threshold
        self.expire_seconds = expire_seconds
        self.voice_alerts = voice_alerts
        self.on_event = on_event
        self.event_history: List[ActivityEvent] = []
        self.max_events = 200
        self.last_voice_alert: Dict[str, float] = {}
        self.voice_cooldown = 12.0  # seconds
        # (signature, address) -> entity id. One entity per address; addresses are
        # only ever grouped by record_probed_model(), never by matching signature.
        self.addr_to_entity: Dict[tuple, str] = {}
        # address -> (most recent RSSI, timestamp); feeds the self-probe proximity guard
        self.address_rssi: Dict[str, tuple] = {}
        # signature -> distinct probed models [{"model_number", "model"}]
        self.signature_models: Dict[str, List[Dict[str, str]]] = {}

    @staticmethod
    def _entity_id(signature: str, address: str) -> str:
        if signature.startswith("mac_"):
            return signature  # already keyed by address
        clean = address.replace(":", "").replace("-", "").lower()
        return f"{signature}-{clean[-6:]}"

    def recent_rssi(self, address: Any, max_age: float) -> Optional[int]:
        """Most recent RSSI for exactly this address, or None if unseen / older than max_age."""
        if not isinstance(address, str):
            return None
        seen = self.address_rssi.get(address.strip().lower())
        if not seen or time.time() - seen[1] > max_age:
            return None
        return seen[0]

    def entity_for_address(self, address: str) -> Optional[Entity]:
        needle = address.lower()
        matches = [e for e in self.entities.values() if any(a.lower() == needle for a in e.addresses)]
        return max(matches, key=lambda e: e.last_seen) if matches else None

    def record_probed_model(self, address: str, model_number: str, model_name: str) -> tuple[Optional[Entity], bool]:
        """
        Records a model number a probe really read from `address`.
        Returns (entity, conflict). On conflict with a model already stored for
        the entity nothing is overwritten; the signature is marked ambiguous.
        Entities are merged only when probes confirmed the SAME model number.
        """
        ent = self.entity_for_address(address)
        if not ent:
            return None, False

        models = self.signature_models.setdefault(ent.signature, [])
        if not any(m["model_number"] == model_number for m in models):
            models.append({"model_number": model_number, "model": model_name})
        # A model this entity already carried also counts as seen.
        if ent.raw_model and not any(m["model_number"] == ent.raw_model for m in models):
            models.insert(0, {"model_number": ent.raw_model, "model": ent.hardware_model or ent.raw_model})

        conflict = bool(ent.raw_model) and ent.raw_model != model_number
        if conflict:
            logger.warning(
                f"Model conflict under {ent.fp}: stored {ent.raw_model}, probe of {address} returned "
                f"{model_number}. Not overwriting; marking ambiguous."
            )
        else:
            ent.raw_model = model_number
            ent.hardware_model = model_name
            if address not in ent.confirmed_addresses:
                ent.confirmed_addresses.append(address)
            for other in list(self.entities.values()):
                if (other is not ent and other.signature == ent.signature
                        and other.raw_model == model_number and other.confirmed_addresses):
                    self._merge_entities(src=other, dst=ent)

        if len(models) > 1:
            for e in self.entities.values():
                if e.signature == ent.signature:
                    e.ambiguous = True
                    e.models_seen = list(models)
        return ent, conflict

    def _merge_entities(self, src: Entity, dst: Entity) -> None:
        """Folds src into dst. Only called for probe-confirmed same-model addresses."""
        for a in src.addresses:
            if a not in dst.addresses:
                dst.addresses.append(a)
        for a in src.confirmed_addresses:
            if a not in dst.confirmed_addresses:
                dst.confirmed_addresses.append(a)
        dst.mac_count = len(dst.addresses)
        dst.first_seen = min(dst.first_seen, src.first_seen)
        dst.count += src.count
        dst.best_rssi = max(dst.best_rssi, src.best_rssi)
        dst.custom_alias = dst.custom_alias or src.custom_alias
        dst.is_watched = dst.is_watched or src.is_watched
        for key, eid in self.addr_to_entity.items():
            if eid == src.fp:
                self.addr_to_entity[key] = dst.fp
        self.entities.pop(src.fp, None)
        logger.info(f"Grouped {src.fp} into {dst.fp}: probes confirmed the same model number")

    def update_profile(self, fp: str, profile_data: Dict[str, Any]) -> None:
        """Sets profile fields on exactly one entity. Nothing is shared with other addresses."""
        entity = self.entities.get(fp)
        if not entity:
            return
        if "hardware_model" in profile_data:
            entity.hardware_model = profile_data["hardware_model"]
        if "raw_model" in profile_data:
            entity.raw_model = profile_data["raw_model"]
        if "firmware" in profile_data:
            entity.firmware = profile_data["firmware"]
        if "battery_level" in profile_data:
            entity.battery_level = profile_data["battery_level"]
        if "custom_alias" in profile_data:
            entity.custom_alias = profile_data["custom_alias"]

    def observe(
        self,
        address: str,
        name: str,
        rssi: int,
        manufacturer_data: Dict[int, bytes],
        service_uuids: List[str],
        service_data: Dict[str, bytes],
    ) -> tuple[Entity, List[ActivityEvent]]:
        now = time.time()
        self.all_seen_addresses.add(address)

        self.address_rssi[address.lower()] = (rssi, now)

        vendor, kind, tracker, signature, apple_dpi = classify_packet(
            name, manufacturer_data, service_uuids, service_data, address
        )
        # The signature is identical across same-model devices, so matching it is
        # not evidence of the same device: every address is its own entity.
        addr_key = (signature, address.lower())
        fp = self.addr_to_entity.get(addr_key) or self._entity_id(signature, address)
        self.addr_to_entity[addr_key] = fp

        raw_hex = ""
        for p in manufacturer_data.values():
            if p:
                raw_hex = p.hex()
                break

        # Compute deterministic angle based on entity id hash
        angle_deg = int(hashlib.md5(fp.encode()).hexdigest()[:6], 16) % 360

        generated_events: List[ActivityEvent] = []

        entity = self.entities.get(fp)
        is_new_entity = entity is None

        auth_tag = apple_dpi.get("auth_tag", "") if apple_dpi else ""

        if is_new_entity:
            entity = Entity(
                fp=fp,
                addresses=[address],
                mac_count=1,
                current_address=address,
                name=name or "",
                vendor=vendor,
                kind=kind,
                tracker=tracker,
                rssi=rssi,
                best_rssi=rssi,
                rssi_ema=float(rssi),
                rssi_history=[rssi],
                first_seen=now,
                last_seen=now,
                count=1,
                continuity=apple_dpi,
                state_label=apple_dpi.get("state_label", "IDLE"),
                angle=float(angle_deg),
                raw_hex=raw_hex,
                prev_rssi=rssi,
                auth_tag=auth_tag,
                signature=signature,
            )
            known_models = self.signature_models.get(signature, [])
            if len(known_models) > 1:
                entity.ambiguous = True
                entity.models_seen = list(known_models)
            self.entities[fp] = entity
        else:
            # Existing entity: update fields
            entity.last_seen = now
            entity.count += 1
            entity.current_address = address
            if auth_tag:
                # Decoded for display only. It is never used to link addresses or
                # to carry a model / alias from one address to another.
                entity.auth_tag = auth_tag
            if name and not entity.name:
                entity.name = name
            if vendor and not entity.vendor:
                entity.vendor = vendor
            if kind:
                entity.kind = kind
            if tracker:
                entity.tracker = True
            if raw_hex:
                entity.raw_hex = raw_hex

            # Update RSSI with Exponential Moving Average (alpha = 0.25)
            entity.prev_rssi = entity.rssi
            entity.rssi = rssi
            entity.best_rssi = max(entity.best_rssi, rssi)
            entity.rssi_ema = round(0.25 * rssi + 0.75 * entity.rssi_ema, 1)
            entity.rssi_history.append(rssi)
            if len(entity.rssi_history) > 30:
                entity.rssi_history.pop(0)

            # Update continuity
            if apple_dpi:
                entity.continuity = apple_dpi
                entity.state_label = apple_dpi.get("state_label", entity.state_label)

        # State Diffing & Event Triggering
        curr_unlocked = apple_dpi.get("screen_unlocked", False) if apple_dpi else False
        curr_airpods = apple_dpi.get("airpods_open", False) if apple_dpi else False
        curr_handoff = apple_dpi.get("handoff_active", False) if apple_dpi else False
        find_my_sep = apple_dpi.get("find_my_separated", None) if apple_dpi else None

        # 1. Screen Unlock Event
        if not entity.prev_screen_unlocked and curr_unlocked:
            entity.prev_screen_unlocked = True
            ev = self._create_event(
                fp=fp,
                action="screen_unlocked",
                description=f"Target {entity.custom_alias or fp} ({rssi} dBm) UNLOCKED SCREEN",
                rssi=rssi,
                level="warn",
                entity=entity,
            )
            generated_events.append(ev)
            self._trigger_voice(f"Target {entity.custom_alias or fp[-4:]} unlocked screen", fp)

        elif entity.prev_screen_unlocked and not curr_unlocked and apple_dpi.get("screen_state_known"):
            entity.prev_screen_unlocked = False
            ev = self._create_event(
                fp=fp,
                action="screen_locked",
                description=f"Target {entity.custom_alias or fp} locked screen",
                rssi=rssi,
                level="info",
                entity=entity,
            )
            generated_events.append(ev)

        # 2. AirPods Opened Event
        if not entity.prev_airpods_open and curr_airpods:
            entity.prev_airpods_open = True
            ev = self._create_event(
                fp=fp,
                action="airpods_open",
                description=f"Target {entity.custom_alias or fp} ({rssi} dBm) opened AirPods / Beats case",
                rssi=rssi,
                level="info",
                entity=entity,
            )
            generated_events.append(ev)

        # 3. Handoff Active Event
        if not entity.prev_handoff and curr_handoff:
            entity.prev_handoff = True
            ev = self._create_event(
                fp=fp,
                action="handoff",
                description=f"Target {entity.custom_alias or fp} ({rssi} dBm) HANDOFF ACTIVE (App Switch / Clipboard)",
                rssi=rssi,
                level="warn",
                entity=entity,
            )
            generated_events.append(ev)

        # 4. Proximity Crossing Event (> -65 dBm)
        if (is_new_entity or entity.prev_rssi <= self.proximity_threshold) and rssi > self.proximity_threshold:
            ev = self._create_event(
                fp=fp,
                action="proximity",
                description=f"Target {entity.custom_alias or fp} entered close proximity ({rssi} dBm)",
                rssi=rssi,
                level="warn",
                entity=entity,
            )
            generated_events.append(ev)
            if rssi >= -60:
                self._trigger_voice(f"Close target detected, {rssi} dBm", fp)

        # 5. AirTag Separated Alert
        if find_my_sep is True and not entity.airtag_warned:
            entity.airtag_warned = True
            ev = self._create_event(
                fp=fp,
                action="airtag",
                description=f"AirTag {fp} ({rssi} dBm) SEPARATED FROM OWNER",
                rssi=rssi,
                level="alert",
                entity=entity,
            )
            generated_events.append(ev)
            self._trigger_voice("Separated AirTag detected nearby", fp)

        # Emit events
        for ev in generated_events:
            self.event_history.append(ev)
            if len(self.event_history) > self.max_events:
                self.event_history.pop(0)
            if self.on_event:
                self.on_event(ev)

        return entity, generated_events

    def _create_event(
        self,
        fp: str,
        action: str,
        description: str,
        rssi: int,
        level: str,
        entity: Optional[Entity] = None,
    ) -> ActivityEvent:
        now = time.time()
        time_str = time.strftime("%H:%M:%S", time.localtime(now))
        ev_id = f"evt_{int(now * 1000)}_{fp}"
        name = (entity.custom_alias or entity.name) if entity else ""
        vendor = entity.vendor if entity else "Unknown"
        kind = entity.kind if entity else "BLE Peripheral"
        ent_dict = entity.to_dict() if entity else None
        return ActivityEvent(
            id=ev_id,
            ts=round(now, 2),
            time_str=time_str,
            fp=fp,
            name=name or "",
            vendor=vendor,
            kind=kind,
            action=action,
            description=description,
            rssi=rssi,
            level=level,
            entity=ent_dict,
        )

    def _trigger_voice(self, phrase: str, fp: str) -> None:
        """Trigger macOS non-blocking voice alert using 'say' command."""
        if not self.voice_alerts:
            return
        now = time.time()
        if now - self.last_voice_alert.get(fp, 0) < self.voice_cooldown:
            return
        self.last_voice_alert[fp] = now
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self._say_async(phrase))
        except RuntimeError:
            # No running event loop
            pass
        except Exception as e:
            logger.debug(f"Say spawn error: {e}")

    async def _say_async(self, phrase: str) -> None:
        try:
            proc = await asyncio.create_subprocess_exec(
                "say", phrase,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await proc.wait()
        except Exception as e:
            logger.debug(f"say command failed: {e}")

    def active_entities(self) -> List[Entity]:
        """Returns all entities seen within expire_seconds."""
        now = time.time()
        return [
            e for e in self.entities.values()
            if now - e.last_seen <= self.expire_seconds
        ]

    def get_radar_state(self) -> Dict[str, Any]:
        """Returns current radar state payload for WebSocket clients."""
        active = self.active_entities()
        active.sort(key=lambda e: (e.state_label == "SCREEN UNLOCKED", -e.rssi), reverse=True)

        unlocked_count = sum(1 for e in active if e.continuity.get("screen_unlocked"))
        airtag_count = sum(1 for e in active if e.tracker or e.continuity.get("is_find_my"))

        return {
            "type": "radar_state",
            "ts": round(time.time(), 2),
            "host": {
                "name": "MacBook Air",
                "center": [0, 0],
            },
            "stats": {
                "total_macs_seen": len(self.all_seen_addresses),
                "unique_entities": len(active),
                "all_time_entities": len(self.entities),
                "unlocked_screens": unlocked_count,
                "airtags_count": airtag_count,
                "voice_alerts_enabled": self.voice_alerts,
            },
            "entities": [e.to_dict() for e in active],
        }


# ============================================================================
# WebSocket Server & Broadcaster
# ============================================================================

class SonarServer:
    def __init__(
        self,
        registry: SonarRegistry,
        http_port: int = 8080,
        ws_port: int = 8765,
        web_dir: Optional[Path] = None,
    ):
        self.registry = registry
        self.http_port = http_port
        self.ws_port = ws_port
        self.web_dir = web_dir or (Path(__file__).parent / "web")
        self.clients: Set[WsConn] = set()
        self.stop_event = asyncio.Event()
        self.ble_scanner: Optional[Any] = None  # paused by gatt_probe during a connection

    async def register_client(self, websocket: WsConn) -> None:
        self.clients.add(websocket)
        logger.info(f"WebSocket client connected: {websocket.remote_address} (Total: {len(self.clients)})")
        try:
            # Send initial radar state and recent event backlog
            init_state = self.registry.get_radar_state()
            await websocket.send(json.dumps(init_state))
            await self.send_trusted_devices(websocket)

            # Send up to 30 recent events
            for ev in self.registry.event_history[-30:]:
                await websocket.send(json.dumps({
                    "type": "activity_event",
                    "event": asdict(ev),
                }))

            async for message in websocket:
                await self.handle_client_message(websocket, message)
        except websockets.exceptions.ConnectionClosed:
            pass
        except Exception as e:
            logger.debug(f"WS error: {e}")
        finally:
            self.clients.discard(websocket)
            logger.info(f"WebSocket client disconnected (Remaining: {len(self.clients)})")

    async def handle_client_message(self, websocket: WsConn, message: str) -> None:
        try:
            data = json.loads(message)
            action = data.get("action")
            if action == "toggle_voice_alerts":
                enabled = data.get("enabled", not self.registry.voice_alerts)
                self.registry.voice_alerts = bool(enabled)
                logger.info(f"Voice alerts toggled to: {self.registry.voice_alerts}")
                await self.broadcast(json.dumps({
                    "type": "config_updated",
                    "voice_alerts_enabled": self.registry.voice_alerts,
                }))

            elif action == "test_voice_alert":
                text = data.get("text", "Ghost Wall radar active")
                await self.registry._say_async(text)

            elif action == "watch_target":
                fp = data.get("fp")
                watched = data.get("watched", True)
                if fp in self.registry.entities:
                    self.registry.entities[fp].is_watched = bool(watched)
                    logger.info(f"Target {fp} watch status: {watched}")

            elif action == "set_alias":
                fp = data.get("fp")
                alias = data.get("alias", "")
                if fp in self.registry.entities:
                    self.registry.entities[fp].custom_alias = alias
                    self.registry.update_profile(fp, {"custom_alias": alias})
                    logger.info(f"Target {fp} alias set to: {alias}")

            elif action == "gatt_probe":
                # Allowlist-gated: gatt_probe.probe() refuses anything not in trusted_devices.json
                asyncio.create_task(self.handle_gatt_probe(websocket, data.get("address")))

            elif action in ("trust_device", "untrust_device"):
                await self.handle_trust_change(websocket, action, data.get("address"), data.get("label", ""))

            elif action == "list_trusted":
                await self.send_trusted_devices(websocket)

            elif action == "simulate_event":
                # For testing and verification
                sim_type = data.get("type", "screen_unlocked")
                self.simulate_event(sim_type)

        except Exception as e:
            logger.warning(f"Error processing client message: {e}")

    async def send_trusted_devices(self, websocket: Optional[WsConn] = None) -> None:
        """Pushes the current trusted_devices.json contents to one client, or to all."""
        msg = json.dumps({"type": "trusted_devices", "devices": gatt_probe.load_trusted()})
        if websocket is not None:
            await websocket.send(msg)
        else:
            await self.broadcast(msg)

    async def handle_trust_change(self, websocket: WsConn, action: str, address: Any, label: Any = "") -> None:
        """Handles trust_device / untrust_device: edits trusted_devices.json and syncs all clients."""
        try:
            if action == "trust_device":
                rssi = self.registry.recent_rssi(address, gatt_probe.RSSI_MAX_AGE_S)
                gatt_probe.trust_device(address, label, rssi=rssi)
            else:
                gatt_probe.untrust_device(address)
        except (ValueError, OSError) as e:
            logger.warning(f"{action} failed for {address!r}: {e}")
            await websocket.send(json.dumps({"type": "trust_error", "address": address, "error": str(e)}))
            return
        await self.send_trusted_devices()

    async def handle_gatt_probe(self, websocket: WsConn, address: Any) -> None:
        """Handles gatt_probe: allowlist-gated real GATT read of the user's own device."""
        try:
            rssi = self.registry.recent_rssi(address, gatt_probe.RSSI_MAX_AGE_S)
            result = await gatt_probe.probe(address, scanner=self.ble_scanner, rssi=rssi)
        except Exception as e:
            logger.error(f"Error in handle_gatt_probe: {e}")
            result = {"type": "probe_result", "status": "error", "address": address, "error": str(e)}

        if result.get("status") == "success":
            self.apply_probe_result(result["address"], result["data"])
            await self.broadcast(json.dumps(self.registry.get_radar_state()))

        try:
            await websocket.send(json.dumps(result))
        except Exception:
            pass

    def apply_probe_result(self, address: str, data: Dict[str, Any]) -> None:
        """Copies values that were really read from the device onto its radar entity."""
        values = data["readable_values"]
        exposed = lambda key: values.get(key) != gatt_probe.NOT_EXPOSED

        conflict = False
        if exposed("model_number"):
            ent, conflict = self.registry.record_probed_model(address, values["model_number"], data["model"])
        else:
            ent = self.registry.entity_for_address(address)
        if not ent:
            return

        if conflict:
            # Different hardware answered under an id that already had a model: the
            # stored profile is left untouched and the id is flagged ambiguous instead.
            description = (
                f"SELF-PROBE {ent.fp}: model {values['model_number']} CONFLICTS with stored "
                f"{ent.raw_model} — multiple devices under this id, nothing overwritten"
            )
        else:
            profile: Dict[str, Any] = {}
            if exposed("model_number"):
                profile["hardware_model"] = data["model"]
                profile["raw_model"] = values["model_number"]
            if exposed("firmware_revision"):
                profile["firmware"] = values["firmware_revision"]
            elif exposed("software_revision"):
                profile["firmware"] = values["software_revision"]
            if exposed("battery_level"):
                profile["battery_level"] = values["battery_level"]
            if profile:
                self.registry.update_profile(ent.fp, profile)
            description = f"SELF-PROBE of trusted device {ent.fp}: model {data['model']}, {len(data['services'])} services"

        ev = self.registry._create_event(
            fp=ent.fp,
            action="gatt_probe",
            description=description,
            rssi=ent.rssi,
            level="warn" if conflict else "info",
            entity=ent,
        )
        self.registry.event_history.append(ev)
        if self.registry.on_event:
            self.registry.on_event(ev)

    def simulate_event(self, sim_type: str = "screen_unlocked") -> None:
        """Injects a simulated event for UI testing."""
        fp = "demo99a1"
        addr = "FA:2B:3C:4D:5E:6F"
        if sim_type == "screen_unlocked":
            # 0x10 Nearby Info with action_code 0x01
            m_data = {0x004C: bytes.fromhex("1003010100")}
            self.registry.observe(addr, "Demonstration iPhone", -48, m_data, [], {})
        elif sim_type == "airpods":
            m_data = {0x004C: bytes.fromhex("0719010203040589a000")}
            self.registry.observe("E0:11:22:33:44:55", "AirPods Pro", -54, m_data, [], {})
        elif sim_type == "handoff":
            m_data = {0x004C: bytes.fromhex("0c0e0102030405060708090a0b0c")}
            self.registry.observe("D1:22:33:44:55:66", "MacBook Pro", -62, m_data, [], {})
        elif sim_type == "airtag":
            m_data = {0x004C: bytes.fromhex("121910" + "00" * 23)}
            self.registry.observe("C0:33:44:55:66:77", "", -60, m_data, [], {})
        elif sim_type == "mac_rotation":
            # Change MAC for demo device
            new_mac = f"F0:{int(time.time()) % 99:02X}:3C:4D:5E:6F"
            m_data = {0x004C: bytes.fromhex("1003010000")}
            self.registry.observe(new_mac, "Demonstration iPhone", -52, m_data, [], {})

    async def broadcast(self, message: str) -> None:
        if not self.clients:
            return
        dead = set()
        for ws in self.clients:
            try:
                await ws.send(message)
            except Exception:
                dead.add(ws)
        self.clients.difference_update(dead)

    def on_activity_event(self, ev: ActivityEvent) -> None:
        """Callback from SonarRegistry when an instant event is triggered."""
        msg = json.dumps({
            "type": "activity_event",
            "event": asdict(ev),
        })
        asyncio.create_task(self.broadcast(msg))

    async def run_radar_broadcast_loop(self) -> None:
        """Broadcasts full radar state to all clients every 1.0s."""
        while not self.stop_event.is_set():
            state = self.registry.get_radar_state()
            msg = json.dumps(state)
            await self.broadcast(msg)
            await asyncio.sleep(1.0)

    async def start_http_server(self) -> web.AppRunner:
        """Starts aiohttp web server serving the frontend UI on port 8080."""
        app = web.Application()

        async def index_handler(request: web.Request) -> web.Response:
            index_path = self.web_dir / "index.html"
            if not index_path.exists():
                return web.Response(
                    text=f"Frontend index.html not found in {self.web_dir}",
                    status=404,
                )
            return web.FileResponse(index_path)

        app.router.add_get("/", index_handler)
        if self.web_dir.exists():
            app.router.add_static("/static", path=str(self.web_dir), name="static")

        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", self.http_port)
        await site.start()
        logger.info(f"HTTP UI Server running at: http://localhost:{self.http_port}")
        return runner

    async def run(self) -> None:
        self.registry.on_event = self.on_activity_event

        # 1. Start HTTP Server
        http_runner = await self.start_http_server()

        # 2. Start WebSocket Server
        ws_server = await websockets.serve(self.register_client, "127.0.0.1", self.ws_port)
        logger.info(f"WebSocket Server running at: ws://localhost:{self.ws_port}")

        # 3. Start BLE Scanner
        try:
            from bleak import BleakScanner

            def on_advertisement(device, adv) -> None:
                try:
                    self.registry.observe(
                        address=device.address,
                        name=adv.local_name or device.name or "",
                        rssi=adv.rssi,
                        manufacturer_data=adv.manufacturer_data,
                        service_uuids=adv.service_uuids or [],
                        service_data=adv.service_data or {},
                    )
                except Exception as e:
                    logger.debug(f"BLE packet parse error: {e}")

            scanner = BleakScanner(detection_callback=on_advertisement)
            await scanner.start()
            self.ble_scanner = scanner
            logger.info("BLE Scanner active — scanning local airspace...")
        except Exception as e:
            logger.error(f"Failed to start BleakScanner: {e}. Running in simulation/synthetic mode.")

        # 4. Start 1-second radar broadcast task
        broadcast_task = asyncio.create_task(self.run_radar_broadcast_loop())

        try:
            await self.stop_event.wait()
        except asyncio.CancelledError:
            pass
        finally:
            logger.info("Shutting down Ghost Wall...")
            broadcast_task.cancel()
            if self.ble_scanner:
                try:
                    await self.ble_scanner.stop()
                except Exception:
                    pass
            ws_server.close()
            await ws_server.wait_closed()
            await http_runner.cleanup()


# ============================================================================
# Entry Point
# ============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="sonar_server",
        description="Ghost Wall — Tactical BLE Sonar & Continuity Profiler",
    )
    parser.add_argument("--http-port", type=int, default=8080, help="HTTP UI port (default: 8080)")
    parser.add_argument("--ws-port", type=int, default=8765, help="WebSocket port (default: 8765)")
    parser.add_argument("--proximity", type=int, default=-65, help="Proximity alert threshold in dBm (default: -65)")
    parser.add_argument("--expire", type=float, default=120.0, help="Device expire seconds (default: 120)")
    parser.add_argument("--no-voice", action="store_true", help="Disable macOS voice alert synthesis")
    parser.add_argument("--simulate", action="store_true", help="Inject demo devices on startup")
    args = parser.parse_args()

    registry = SonarRegistry(
        proximity_threshold=args.proximity,
        expire_seconds=args.expire,
        voice_alerts=not args.no_voice,
    )

    server = SonarServer(
        registry=registry,
        http_port=args.http_port,
        ws_port=args.ws_port,
    )

    if args.simulate:
        logger.info("Injecting demo entities on startup...")
        server.simulate_event("screen_unlocked")
        server.simulate_event("airpods")
        server.simulate_event("handoff")

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        loop.run_until_complete(server.run())
    except KeyboardInterrupt:
        logger.info("Interrupted by user. Exiting.")
    finally:
        loop.close()


if __name__ == "__main__":
    main()
