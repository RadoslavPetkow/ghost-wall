"""Local Airspace Monitor — CLI.   python -m lam --help"""
from __future__ import annotations

import argparse
import asyncio
import time

from rich.console import Console
from rich.live import Live
from rich.table import Table

from .ble import run_ble
from .core import Event, Registry

console = Console()


def fmt_age(sec: float) -> str:
    sec = int(sec)
    return f"{sec}s" if sec < 60 else f"{sec // 60}m{sec % 60:02d}s"


def bar(rssi: int) -> str:
    n = max(0, min(8, (rssi + 100) // 7))
    return "█" * n + "·" * (8 - n)


def render(reg: Registry) -> Table:
    devs = reg.active()
    t = Table(title=f"Local Airspace Monitor · BLE · {len(devs)} устройства · праг {reg.near_rssi} dBm",
              expand=True)
    for col in ("", "Адрес", "Име", "Производител", "Тип", "RSSI", "Сигнал", "Видяно", "Преди", "FP"):
        t.add_column(col, no_wrap=True, overflow="ellipsis")
    now = time.time()
    for d in devs[:40]:
        near = d.rssi >= reg.near_rssi
        style = ("bold red" if d.tracker_warned else "yellow" if d.tracker and near
                 else "" if near else "dim")
        t.add_row("⚠" if d.tracker_warned else "•" if d.tracker else "", d.key[-17:], d.name[:18], d.vendor, d.kind[:50],
                  str(d.rssi), bar(d.rssi), fmt_age(d.age), fmt_age(now - d.last_seen),
                  d.fingerprint, style=style)
    return t


def on_event(ev: Event) -> None:
    d = ev.device
    color = "red" if ev.level == "warn" else "cyan"
    who = " · ".join(x for x in (d.name, d.vendor, d.kind) if x) or "неизвестно"
    console.print(f"[{color}]{time.strftime('%H:%M:%S')} {ev.text}:[/] {who} "
                  f"({d.key[-8:]}, {d.rssi} dBm)" + ("\a" if ev.level == "warn" else ""))


async def main_async(args) -> None:
    reg = Registry(near_rssi=args.rssi, tracker_minutes=args.tracker_minutes,
                   expire_seconds=args.expire, on_event=on_event, log_path=args.log)
    stop = asyncio.Event()
    task = asyncio.create_task(run_ble(reg, stop))
    try:
        with Live(render(reg), console=console, refresh_per_second=2) as live:
            while not task.done():
                await asyncio.sleep(0.5)
                live.update(render(reg))
        await task  # покажи грешката, ако скенерът е паднал
    finally:
        stop.set()


def main() -> None:
    p = argparse.ArgumentParser(prog="lam", description="Local Airspace Monitor")
    p.add_argument("mode", nargs="?", default="ble", choices=["ble", "wifi"],
                   help="ble = радар на живо (по подразбиране); wifi = кратка сесия в monitor mode")
    p.add_argument("--rssi", type=int, default=-70,
                   help="праг за 'наблизо' в dBm (по подразбиране -70; -55 е ~1-2 м)")
    p.add_argument("--tracker-minutes", type=float, default=10,
                   help="след колко минути тракер се смята за 'следящ'")
    p.add_argument("--expire", type=float, default=120,
                   help="след колко секунди без сигнал устройство изчезва от таблицата")
    p.add_argument("--log", help="JSONL файл за алармите (по подразбиране нищо не се записва)")
    w = p.add_argument_group("wifi")
    w.add_argument("--seconds", type=int, default=40, help="продължителност на Wi-Fi сесията")
    w.add_argument("--iface", default="en0")
    w.add_argument("--mine", action="append", metavar="SSID",
                   help="име на твоя мрежа (може няколко пъти); запомня се")
    w.add_argument("--learn", action="store_true",
                   help="добави новите BSSID-та на --mine мрежите като доверени")
    w.add_argument("--channel", type=int, help="стой на един канал (по-добро за deauth)")
    w.add_argument("--dwell", type=float, default=0.35, help="секунди на канал при обхождане")
    w.add_argument("--deauth", type=int, default=10, help="праг: deauth кадри за 10 s")
    w.add_argument("--no-rejoin", action="store_true", help="не рестартирай Wi-Fi накрая")
    args = p.parse_args()
    if args.mode == "wifi":
        from .wifi import run_wifi
        return run_wifi(args)
    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
