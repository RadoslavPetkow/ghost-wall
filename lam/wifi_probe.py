"""Тест: какво ни дава macOS при Wi-Fi сканиране.   python -m lam.wifi_probe

macOS крие SSID и BSSID от програми без разрешение за Location Services.
Скриптът иска разрешението, сканира веднъж и показва какво реално се вижда.
Нищо не се записва и нищо не се изпраща.
"""
from __future__ import annotations

import sys
import time
from collections import defaultdict

AUTH = {0: "не е питано", 1: "ограничено", 2: "ОТКАЗАНО", 3: "разрешено", 4: "разрешено"}


def location_status(wait: float = 20.0) -> int:
    import CoreLocation
    from Foundation import NSDate, NSRunLoop

    if not CoreLocation.CLLocationManager.locationServicesEnabled():
        print("Location Services са изключени за целия Mac.")
        return 2
    mgr = CoreLocation.CLLocationManager.alloc().init()
    status = mgr.authorizationStatus()
    if status == 0:
        print("Искам разрешение за Location Services (виж за системен прозорец)...")
        mgr.requestWhenInUseAuthorization()
        mgr.startUpdatingLocation()
        end = time.time() + wait
        while time.time() < end and mgr.authorizationStatus() == 0:
            NSRunLoop.currentRunLoop().runUntilDate_(NSDate.dateWithTimeIntervalSinceNow_(0.5))
        mgr.stopUpdatingLocation()
        status = mgr.authorizationStatus()
    return int(status)


def security_of(net) -> str:
    import CoreWLAN

    names = [("WPA3", "kCWSecurityWPA3Personal"), ("WPA2/3", "kCWSecurityWPA3Transition"),
             ("WPA2", "kCWSecurityWPA2Personal"), ("WPA2-Ent", "kCWSecurityWPA2Enterprise"),
             ("WPA", "kCWSecurityWPAPersonal"), ("WEP", "kCWSecurityWEP"),
             ("ОТВОРЕНА", "kCWSecurityNone")]
    for label, const in names:
        value = getattr(CoreWLAN, const, None)
        if value is not None and net.supportsSecurity_(value):
            return label
    return "?"


def main() -> None:
    if sys.platform != "darwin":
        sys.exit("Този тест е само за macOS.")
    import CoreWLAN

    status = location_status()
    print(f"Location Services за този Python: {AUTH.get(status, status)}")

    iface = CoreWLAN.CWWiFiClient.sharedWiFiClient().interface()
    if iface is None:
        sys.exit("Не намирам Wi-Fi интерфейс.")
    print(f"Интерфейс: {iface.interfaceName()} · свързан към: {iface.ssid()!r} / {iface.bssid()!r}")

    nets, err = iface.scanForNetworksWithName_error_(None, None)
    if err is not None or nets is None:
        sys.exit(f"Сканирането не успя: {err}")
    nets = sorted(nets, key=lambda n: -n.rssiValue())

    by_ssid = defaultdict(list)
    print(f"\n{'SSID':<28} {'BSSID':<18} {'RSSI':>5} {'Кан':>4}  Защита")
    for n in nets:
        ch = n.wlanChannel()
        ssid, bssid = n.ssid(), n.bssid()
        by_ssid[ssid].append(bssid)
        print(f"{str(ssid)[:27]:<28} {str(bssid):<18} {n.rssiValue():>5} "
              f"{ch.channelNumber() if ch else '?':>4}  {security_of(n)}")

    no_ssid = sum(1 for n in nets if n.ssid() is None)
    no_bssid = sum(1 for n in nets if n.bssid() is None)
    print(f"\nОбщо мрежи: {len(nets)} · без SSID: {no_ssid} · без BSSID: {no_bssid}")
    multi = {s: b for s, b in by_ssid.items() if s and len(b) > 1}
    if multi:
        print("SSID с повече от една точка за достъп:",
              ", ".join(f"{s} ({len(b)})" for s, b in multi.items()))
    if nets and no_bssid == len(nets):
        print("\nРЕЗУЛТАТ: macOS крие BSSID-тата -> трябва разрешение за Location Services.")
    elif nets:
        print("\nРЕЗУЛТАТ: виждаме SSID и BSSID -> Evil Twin проверката е възможна така.")


if __name__ == "__main__":
    main()
