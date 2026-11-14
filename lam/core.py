"""Общо ядро: всеки източник (BLE сега, Wi-Fi после) подава Sighting към Registry."""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Callable, Optional


@dataclass
class Sighting:
    source: str            # "ble" | "wifi"
    key: str               # адрес / BSSID
    rssi: int
    name: str = ""
    vendor: str = ""
    kind: str = ""         # напр. "Find My тракер", "слушалки"
    tracker: bool = False
    fingerprint: str = ""  # стабилни белези на рекламния пакет
    ts: float = field(default_factory=time.time)


@dataclass
class Device:
    source: str
    key: str
    first_seen: float
    last_seen: float
    rssi: int
    best_rssi: int
    name: str = ""
    vendor: str = ""
    kind: str = ""
    tracker: bool = False
    fingerprint: str = ""
    count: int = 0
    announced: bool = False        # вдигната ли е аларма "ново устройство"
    tracker_warned: bool = False   # вдигната ли е аларма "тракер стои наблизо"

    @property
    def age(self) -> float:
        return self.last_seen - self.first_seen


@dataclass
class Event:
    ts: float
    level: str   # "info" | "warn"
    type: str    # "new_device" | "tracker_nearby" | "tracker_persistent"
    device: Device
    text: str


class Registry:
    def __init__(
        self,
        near_rssi: int = -70,
        tracker_minutes: float = 10.0,
        expire_seconds: float = 120.0,
        on_event: Optional[Callable[[Event], None]] = None,
        log_path: Optional[str] = None,
    ):
        self.devices: dict[tuple[str, str], Device] = {}
        self.near_rssi = near_rssi
        self.tracker_seconds = tracker_minutes * 60
        self.expire_seconds = expire_seconds
        self.on_event = on_event
        self.log_path = log_path
        self.started = time.time()
        self.warmup = 15.0  # първите секунди всичко е "ново" -> без аларми

    def observe(self, s: Sighting) -> Device:
        k = (s.source, s.key)
        d = self.devices.get(k)
        if d is None:
            d = Device(s.source, s.key, s.ts, s.ts, s.rssi, s.rssi)
            self.devices[k] = d
        d.last_seen = s.ts
        d.rssi = s.rssi
        d.best_rssi = max(d.best_rssi, s.rssi)
        d.count += 1
        d.name = s.name or d.name
        d.vendor = s.vendor or d.vendor
        d.kind = s.kind or d.kind
        d.tracker = s.tracker if s.kind else d.tracker
        d.fingerprint = s.fingerprint or d.fingerprint
        self._check(d)
        return d

    def _check(self, d: Device) -> None:
        in_warmup = d.first_seen - self.started < self.warmup
        if not d.announced and d.rssi >= self.near_rssi:
            d.announced = True
            if not in_warmup:
                self._emit("info", "new_device", d,
                           "Възможен тракер наблизо" if d.tracker else "Ново устройство наблизо")
        # Истинската аларма: тракер, който е близо И не си тръгва
        if (d.tracker and not d.tracker_warned and d.age >= self.tracker_seconds
                and d.rssi >= self.near_rssi):
            d.tracker_warned = True
            self._emit("warn", "tracker_persistent", d,
                       f"Тракер стои около теб вече {int(d.age // 60)} мин")

    def _emit(self, level: str, type_: str, d: Device, text: str) -> None:
        ev = Event(time.time(), level, type_, d, text)
        if self.log_path:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps({
                    "ts": round(ev.ts, 1), "level": level, "type": type_,
                    "source": d.source, "key": d.key, "name": d.name,
                    "vendor": d.vendor, "kind": d.kind, "rssi": d.rssi,
                }, ensure_ascii=False) + "\n")
        if self.on_event:
            self.on_event(ev)

    def active(self) -> list[Device]:
        now = time.time()
        return sorted(
            (d for d in self.devices.values() if now - d.last_seen <= self.expire_seconds),
            key=lambda d: (not d.tracker, -d.rssi),
        )
