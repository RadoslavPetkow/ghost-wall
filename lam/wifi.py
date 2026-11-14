"""Wi-Fi сесия: кратък запис в monitor mode през tcpdump -> Evil Twin + deauth проверка.

macOS крие SSID/BSSID от обикновеното сканиране, затова четем суровите beacon
кадри. Докато трае сесията, лаптопът няма интернет. Нужен е sudo (за tcpdump).
"""
from __future__ import annotations

import json
import os
import queue
import re
import subprocess
import sys
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path

BASELINE = Path.home() / ".lam" / "wifi.json"
FILTER = "type mgt and (subtype beacon or subtype probe-resp or subtype deauth or subtype disassoc)"

RE_FREQ = re.compile(r"\b(\d{4}) MHz")
RE_SIG = re.compile(r"(-\d+)dBm signal")
RE_BSSID = re.compile(r"BSSID:([0-9a-f:]{17})")
RE_SA = re.compile(r"SA:([0-9a-f:]{17})")
RE_DA = re.compile(r"DA:([0-9a-f:]{17}|Broadcast)")
RE_CH = re.compile(r"CH: (\d+)")
RE_SSID = re.compile(r"(?:Beacon|Probe Response) \((.*)\) \[")


def chan_of(freq: int) -> int:
    if freq == 2484:
        return 14
    return (freq - 2407) // 5 if freq < 3000 else (freq - 5000) // 5


@dataclass
class Frame:
    kind: str            # "beacon" | "deauth"
    bssid: str
    channel: int = 0
    signal: int = -100
    ssid: str = ""
    privacy: bool = True
    adhoc: bool = False
    broadcast: bool = False
    radio_ch: int = 0    # каналът, на който радиото реално е чуло кадъра
    ts: float = field(default_factory=time.time)


def parse_line(line: str):
    """Един ред от `tcpdump -e` -> Frame или None."""
    b = RE_BSSID.search(line)
    if not b:
        return None
    f = RE_FREQ.search(line)
    s = RE_SIG.search(line)
    ch = chan_of(int(f.group(1))) if f else 0
    sig = int(s.group(1)) if s else -100
    if "DeAuthentication" in line or "Disassociation" in line:
        da = RE_DA.search(line)
        return Frame("deauth", b.group(1), ch, sig, broadcast=bool(da and da.group(1) == "Broadcast"))
    m = RE_SSID.search(line)
    if not m:
        return None
    radio = ch
    tail = line[m.end():]
    ds = RE_CH.search(tail)  # каналът, който самата точка обявява (без "разливане")
    if ds:
        ch = int(ds.group(1))
    return Frame("beacon", b.group(1), ch, sig, ssid=m.group(1),
                 privacy="PRIVACY" in tail, adhoc=" IBSS" in tail, radio_ch=radio)


def related(a: str, b: str) -> bool:
    """Два BSSID-а вероятно са от един и същ рутер (друга честота / гост мрежа)."""
    x, y = a.split(":"), b.split(":")
    return x[1:] == y[1:] or x[:5] == y[:5] or x[1:5] == y[1:5]


@dataclass
class AP:
    ssid: str
    bssid: str
    channels: set = field(default_factory=set)
    signal: int = -100
    privacy: bool = True
    adhoc: bool = False
    beacons: int = 0


class WifiAnalyzer:
    def __init__(self, mine: dict, deauth_threshold: int = 10, window: float = 10.0):
        self.mine = mine                      # {ssid: {bssid: {...}}}
        self.aps: dict[tuple[str, str], AP] = {}
        self.deauth_times: dict[str, deque] = defaultdict(deque)
        self.deauth_total: dict[str, int] = defaultdict(int)
        self.deauth_flagged: set[str] = set()
        self.threshold, self.window = deauth_threshold, window
        self.alerts: list[tuple[str, str]] = []   # (level, text)

    def feed(self, fr: Frame) -> None:
        if fr.kind == "deauth":
            q = self.deauth_times[fr.bssid]
            q.append(fr.ts)
            self.deauth_total[fr.bssid] += 1
            while q and fr.ts - q[0] > self.window:
                q.popleft()
            if len(q) >= self.threshold and fr.bssid not in self.deauth_flagged:
                self.deauth_flagged.add(fr.bssid)
                self.alerts.append(("warn", f"Deauth атака? {len(q)} кадъра за {self.window:.0f} s "
                                            f"към/от {fr.bssid} (канал {fr.channel})"))
            return
        ap = self.aps.setdefault((fr.ssid, fr.bssid), AP(fr.ssid, fr.bssid))
        ap.channels.add(fr.channel)
        ap.signal = max(ap.signal, fr.signal)
        ap.privacy, ap.adhoc = fr.privacy, fr.adhoc
        ap.beacons += 1

    def finish(self, learn: set[str]) -> None:
        """Сравнява видяното с базата за 'моите' мрежи. learn = SSID-та за (до)обучение."""
        for ssid, known in self.mine.items():
            seen = [ap for ap in self.aps.values() if ap.ssid == ssid]
            if not seen:
                self.alerts.append(("info", f"„{ssid}“ не беше чута в тази сесия "
                                            "(възможно е да е на честота, която сесията не покри)."))
                continue
            for ap in seen:
                if not ap.privacy:
                    self.alerts.append(("warn", f"EVIL TWIN? „{ssid}“ се излъчва БЕЗ защита от "
                                                f"{ap.bssid} (канал {sorted(ap.channels)}, {ap.signal} dBm)"))
                if ap.bssid in known:
                    continue
                if ssid in learn or not known:
                    known[ap.bssid] = {"channels": sorted(ap.channels), "privacy": ap.privacy,
                                       "added": time.strftime("%Y-%m-%d %H:%M")}
                    self.alerts.append(("info", f"Запомних {ap.bssid} като точка за достъп на „{ssid}“."))
                elif any(related(ap.bssid, k) for k in known):
                    self.alerts.append(("info", f"Нов BSSID {ap.bssid} за „{ssid}“, но прилича на твоя "
                                                f"рутер (друга честота?). Добави го с --learn, ако е твой."))
                else:
                    self.alerts.append(("warn", f"EVIL TWIN? Непознат BSSID {ap.bssid} излъчва „{ssid}“ "
                                                f"(канал {sorted(ap.channels)}, {ap.signal} dBm)"))


# ---------- macOS: управление на картата ----------

class Radio:
    """Разкачане и смяна на канал през CoreWLAN. Всичко е 'best effort'."""

    def __init__(self, name: str):
        self.name, self.iface, self.chans = name, None, {}
        try:
            import CoreWLAN
            self.iface = CoreWLAN.CWWiFiClient.sharedWiFiClient().interfaceWithName_(name)
            for c in self.iface.supportedWLANChannels() or []:
                if c.channelWidth() == 1 and c.channelBand() in (1, 2):  # 20 MHz; 2.4 и 5 GHz
                    self.chans[int(c.channelNumber())] = c
        except Exception as e:  # noqa: BLE001
            print(f"(CoreWLAN не е достъпен: {e} -> без смяна на канали)")

    def disassociate(self) -> None:
        try:
            if self.iface is not None:
                self.iface.disassociate()
        except Exception:  # noqa: BLE001
            pass

    def set_channel(self, n: int) -> bool:
        c = self.chans.get(n)
        if c is None or self.iface is None:
            return False
        try:
            ok, _err = self.iface.setWLANChannel_error_(c, None)
            return bool(ok)
        except Exception:  # noqa: BLE001
            return False

    def current(self) -> int:
        try:
            return int(self.iface.wlanChannel().channelNumber())
        except Exception:  # noqa: BLE001
            return 0

    def rejoin(self) -> None:
        for state in ("off", "on"):
            subprocess.run(["networksetup", "-setairportpower", self.name, state],
                           capture_output=True)
            time.sleep(1)


def load_mine() -> dict:
    try:
        return json.loads(BASELINE.read_text(encoding="utf-8")).get("mine", {})
    except (OSError, ValueError):
        return {}


def save_mine(mine: dict) -> None:
    BASELINE.parent.mkdir(parents=True, exist_ok=True)
    BASELINE.write_text(json.dumps({"mine": mine}, ensure_ascii=False, indent=2), encoding="utf-8")


def run_wifi(args) -> None:
    from rich.console import Console
    from rich.table import Table

    from rich.markup import escape

    console = Console(emoji=False)
    if sys.platform != "darwin":
        sys.exit("Wi-Fi сесията засега е само за macOS.")
    if not re.fullmatch(r"[a-z0-9]+", args.iface):
        sys.exit("Невалидно име на интерфейс.")

    mine = load_mine()
    for ssid in args.mine or []:
        mine.setdefault(ssid, {})
    learn = set(args.mine or []) if args.learn else set()

    console.print(f"Wi-Fi сесия {args.seconds} s на {args.iface}. [yellow]Интернетът ще прекъсне.[/]")
    if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode != 0:
        console.print("sudo ще поиска паролата на Mac-а (пиши я САМО ако видиш 'Password:').")
        if subprocess.run(["sudo", "-v"]).returncode != 0:
            sys.exit("Без sudo няма monitor mode.")

    radio = Radio(args.iface)
    radio.disassociate()
    cmd = (f"tcpdump -I -i {args.iface} -l -e -n '{FILTER}' 2>/dev/null & p=$!; "
           f"sleep {int(args.seconds)}; kill $p 2>/dev/null; wait $p 2>/dev/null")
    proc = subprocess.Popen(["sudo", "sh", "-c", cmd], stdout=subprocess.PIPE, text=True,
                            errors="replace")
    lines: queue.Queue = queue.Queue()
    threading.Thread(target=lambda: [lines.put(l) for l in proc.stdout], daemon=True).start()

    plan = [args.channel] if args.channel else (
        [c for c in (1, 6, 11, 2, 3, 4, 5, 7, 8, 9, 10, 12, 13, 36, 40, 44, 48, 52, 56, 60, 64,
                     100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140) if c in radio.chans])
    an = WifiAnalyzer(mine, deauth_threshold=args.deauth)
    hop_ok = hop_fail = n = 0
    failed: set[int] = set()
    heard: dict[int, int] = defaultdict(int)     # канал на радиото -> кадри
    actual: dict[int, set] = defaultdict(set)    # поискан канал -> какво докладва картата
    i = 0
    try:
        while proc.poll() is None:
            if plan:
                radio.disassociate()
                if radio.set_channel(plan[i % len(plan)]):
                    hop_ok += 1
                    time.sleep(0.05)
                    actual[plan[i % len(plan)]].add(radio.current())
                else:
                    hop_fail += 1
                    failed.add(plan[i % len(plan)])
                i += 1
            end = time.time() + (args.dwell if len(plan) > 1 else 1.0)
            while time.time() < end:
                try:
                    fr = parse_line(lines.get(timeout=0.1))
                except queue.Empty:
                    continue
                if fr:
                    an.feed(fr)
                    n += 1
                    heard[fr.radio_ch] += 1
    except KeyboardInterrupt:
        pass
    finally:
        while not lines.empty():
            fr = parse_line(lines.get())
            if fr:
                an.feed(fr)
                n += 1
        if not args.no_rejoin:
            console.print("Връщам Wi-Fi връзката...")
            radio.rejoin()

    bands = {"2.4 GHz" if c <= 14 else "5 GHz" for c in heard if c}
    covered = " и ".join(sorted(bands)) or "нищо"
    an.finish(learn)
    if args.mine or learn or any(mine.values()):
        save_mine(mine)

    t = Table(title=f"Wi-Fi · {len(an.aps)} точки за достъп · {n} кадъра · "
                    f"смяна на канал: {hop_ok} успешни / {hop_fail} неуспешни")
    for col in ("", "SSID", "BSSID", "Канал", "Сигнал", "Защита", "Deauth"):
        t.add_column(col, no_wrap=True)
    for ap in sorted(an.aps.values(), key=lambda a: -a.signal):
        is_mine = ap.ssid in mine
        known = ap.bssid in mine.get(ap.ssid, {})
        mark = "★" if known else ("?" if is_mine else "")
        sec = "да" if ap.privacy else "[red]ОТВОРЕНА[/]"
        if ap.adhoc:
            sec += " (ad-hoc)"
        t.add_row(mark, escape(ap.ssid) or "(скрита)", ap.bssid, ",".join(map(str, sorted(ap.channels))),
                  str(ap.signal), sec, str(an.deauth_total.get(ap.bssid, "")),
                  style="bold" if is_mine else "")
    console.print(t)
    n5 = sum(1 for ap in an.aps.values() if max(ap.channels) > 14)
    wrong = {k: sorted(v) for k, v in actual.items() if v != {k}}
    console.print("Кадри по канал на радиото: "
                  + (" ".join(f"{c}:{heard[c]}" for c in sorted(heard)) or "няма"))
    console.print("Картата докладва друг канал от поискания: "
                  + (" ".join(f"{k}->{v}" for k, v in sorted(wrong.items())) or "никъде"))
    console.print(f"Обходени канали: {len(plan)} · точки на 5 GHz: {n5}"
                  + (f" · неуспешни канали: {sorted(failed)}" if failed else ""))
    if n == 0:
        console.print("[red]Няма уловени кадри.[/] Разкачи се ръчно от мрежата "
                      "(Option + клик на Wi-Fi иконата -> Disconnect) и пусни пак с --no-rejoin.")
    for level, text in an.alerts:
        console.print(("[red]⚠ " if level == "warn" else "[cyan]• ") + text + "[/]")
    if not mine:
        console.print("\nЗа да пазя твоята мрежа, пусни пак с името ѝ:  "
                      "python -m lam wifi --mine \"ИМЕ НА МРЕЖАТА\"")
    elif not any(l == "warn" for l, _ in an.alerts):
        console.print(f"[green]Няма признаци за Evil Twin или deauth атака на {covered}.[/]")
    if len(bands) < 2:
        console.print(f"[yellow]Покрита честота: само {covered}.[/] Вграденият чип слуша само "
                      "честотата, на която лаптопът е бил свързан; другата не е проверена.")
