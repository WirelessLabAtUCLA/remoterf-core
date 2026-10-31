"""
Command-line interface for the RSSI collector tool.
"""

import sys
import time
import json
import csv
import argparse
from typing import List, Optional
from collections import deque

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from rich.text import Text

from .scanner import RSSIScanner, AccessPoint
from .dongle import find_usb_wifi_dongles, get_default_usb_dongle
from .safety import get_default_route_info


def make_signal_bar(quality_pct: int, length: int = 10) -> str:
    """Creates a visual bar like [██████░░░░]"""
    filled = int(round((quality_pct / 100.0) * length))
    filled = min(length, max(0, filled))
    empty = length - filled
    return "█" * filled + "░" * empty


def get_signal_style(dbm: float) -> str:
    if dbm >= -60:
        return "bold green"
    elif dbm >= -75:
        return "yellow"
    elif dbm >= -85:
        return "bold yellow"
    else:
        return "bold red"


def create_access_point_table(
    aps: List[AccessPoint],
    title: str = "Nearby Wi-Fi Networks",
    limit: Optional[int] = None
) -> Table:
    table = Table(title=title, show_header=True, header_style="bold cyan")
    table.add_column("SSID", style="bold white", min_width=18)
    table.add_column("BSSID", style="dim")
    table.add_column("RSSI (dBm)", justify="right")
    table.add_column("Quality", justify="left")
    table.add_column("Chan", justify="right")
    table.add_column("Freq", justify="right")
    table.add_column("Band", justify="center")
    table.add_column("Security", style="magenta")
    table.add_column("Age", justify="right", style="dim")

    display_aps = aps[:limit] if limit else aps
    for ap in display_aps:
        sig_style = get_signal_style(ap.signal_dbm)
        bar = make_signal_bar(ap.quality_pct)
        quality_str = f"[{sig_style}]{bar} {ap.quality_pct}%[/{sig_style}]"
        sig_str = f"[{sig_style}]{ap.signal_dbm:5.1f} dBm[/{sig_style}]"
        age_str = f"{ap.last_seen_ms} ms" if ap.last_seen_ms is not None else "--"
        chan_str = str(ap.channel) if ap.channel is not None else "--"
        freq_str = f"{ap.freq_mhz} MHz" if ap.freq_mhz is not None else "--"

        table.add_row(
            ap.ssid,
            ap.bssid,
            sig_str,
            quality_str,
            chan_str,
            freq_str,
            ap.band,
            ap.security,
            age_str
        )
    return table


def run_scan_command(args: argparse.Namespace) -> None:
    console = Console()
    try:
        scanner = RSSIScanner(interface=args.interface)
    except Exception as e:
        console.print(f"[bold red]Initialization Error:[/bold red] {e}")
        sys.exit(1)

    with console.status(f"[cyan]Scanning Wi-Fi channels using {scanner.interface}...[/cyan]"):
        results = scanner.scan(rescan=not args.cached)

    # Apply filters
    if args.filter:
        flt = args.filter.lower()
        results = [ap for ap in results if flt in ap.ssid.lower() or flt in ap.bssid.lower()]
    if args.min_rssi is not None:
        results = [ap for ap in results if ap.signal_dbm >= args.min_rssi]
    if args.band:
        results = [ap for ap in results if args.band in ap.band]

    # Sort
    if args.sort == "ssid":
        results.sort(key=lambda ap: ap.ssid.lower())
    elif args.sort == "channel":
        results.sort(key=lambda ap: ap.channel or 0)
    elif args.sort == "freq":
        results.sort(key=lambda ap: ap.freq_mhz or 0)
    else:  # default signal
        results.sort(key=lambda ap: ap.signal_dbm, reverse=True)

    if args.json:
        print(json.dumps([ap.to_dict() for ap in results], indent=2))
        return

    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    "iso_timestamp", "bssid", "ssid", "signal_dbm",
                    "quality_pct", "freq_mhz", "channel", "band",
                    "security", "last_seen_ms", "timestamp"
                ]
            )
            writer.writeheader()
            for ap in results:
                writer.writerow(ap.to_dict())
        console.print(f"[green]Saved {len(results)} records to {args.csv}[/green]")

    table = create_access_point_table(
        results,
        title=f"Wi-Fi Scan Results ({scanner.interface}) - {len(results)} APs found",
        limit=args.limit
    )
    console.print(table)


def run_monitor_command(args: argparse.Namespace) -> None:
    console = Console()
    try:
        scanner = RSSIScanner(interface=args.interface)
    except Exception as e:
        console.print(f"[bold red]Initialization Error:[/bold red] {e}")
        sys.exit(1)

    csv_writer = None
    csv_file = None
    if args.csv:
        csv_file = open(args.csv, "w", newline="", encoding="utf-8")
        csv_writer = csv.DictWriter(
            csv_file,
            fieldnames=[
                "iso_timestamp", "bssid", "ssid", "signal_dbm",
                "quality_pct", "freq_mhz", "channel", "band",
                "security", "last_seen_ms", "timestamp"
            ]
        )
        csv_writer.writeheader()
        csv_file.flush()

    rssi_history: deque = deque(maxlen=30)
    console.print(f"[bold green]Starting RSSI monitor on interface '{scanner.interface}'...[/bold green]")
    if args.ssid:
        console.print(f"[cyan]Target SSID:[/cyan] {args.ssid}")
    if args.bssid:
        console.print(f"[cyan]Target BSSID:[/cyan] {args.bssid}")
    console.print(f"[dim]Press Ctrl+C to stop.[/dim]\n")

    iteration = 0
    try:
        for aps in scanner.monitor(
            interval=args.interval,
            target_ssid=args.ssid,
            target_bssid=args.bssid,
            count=args.count
        ):
            iteration += 1
            now_str = time.strftime("%H:%M:%S")

            if csv_writer and csv_file:
                for ap in aps:
                    csv_writer.writerow(ap.to_dict())
                csv_file.flush()

            if args.ssid or args.bssid:
                # Target tracking view
                if aps:
                    best = aps[0]
                    rssi_history.append(best.signal_dbm)
                    avg_rssi = sum(rssi_history) / len(rssi_history)
                    min_rssi = min(rssi_history)
                    max_rssi = max(rssi_history)
                    sig_style = get_signal_style(best.signal_dbm)
                    bar = make_signal_bar(best.quality_pct, length=20)

                    # Simple sparkline representation
                    history_str = " ".join([f"{v:.0f}" for v in list(rssi_history)[-8:]])

                    console.print(
                        f"[{now_str}] [bold white]{best.ssid:<20}[/bold white] "
                        f"[dim]{best.bssid}[/dim] | "
                        f"[{sig_style}]{best.signal_dbm:6.1f} dBm[/{sig_style}] "
                        f"[{sig_style}][{bar} {best.quality_pct}%][/{sig_style}] | "
                        f"Avg: {avg_rssi:5.1f} dBm (Min: {min_rssi:.0f}, Max: {max_rssi:.0f}) | "
                        f"Chan: {best.channel or '--'} ({best.band}) | "
                        f"Recent: [{history_str}]"
                    )
                else:
                    target_name = args.ssid or args.bssid
                    console.print(f"[{now_str}] Target '{target_name}' not detected in this scan.")
            else:
                # General monitor table view
                table = create_access_point_table(
                    aps,
                    title=f"Scan #{iteration} at {now_str} ({len(aps)} APs)",
                    limit=args.limit or 15
                )
                console.print(table)

    except KeyboardInterrupt:
        console.print("\n[yellow]Monitoring stopped by user.[/yellow]")
    finally:
        if csv_file:
            csv_file.close()
            console.print(f"[green]Data successfully saved to {args.csv}[/green]")


def run_info_command(args: argparse.Namespace) -> None:
    console = Console()
    console.print(Panel.fit("[bold cyan]USB Wi-Fi & Network Safety Information[/bold cyan]"))

    # Ethernet Route status
    route_info = get_default_route_info()
    console.print("\n[bold]Current Network Routing (Protected):[/bold]")
    console.print(f"  • Default Gateway Interface: [bold green]{route_info.get('interface')}[/bold green]")
    console.print(f"  • Gateway IP: {route_info.get('gateway')}")
    console.print(f"  • Routing Rule: [dim]{route_info.get('raw')}[/dim]")

    # Detected USB Wi-Fi dongles
    dongles = find_usb_wifi_dongles()
    console.print(f"\n[bold]Detected USB Wi-Fi Adapters ({len(dongles)}):[/bold]")
    if not dongles:
        console.print("  [bold red]No USB Wi-Fi dongles found.[/bold red]")
    else:
        for i, d in enumerate(dongles, 1):
            console.print(f"  [cyan]{i}. Interface:[/cyan] [bold]{d.interface}[/bold]")
            console.print(f"     Device:       {d.manufacturer} {d.product_name}")
            console.print(f"     USB ID:       {d.vendor_id}:{d.product_id}")
            console.print(f"     Linux Driver: {d.driver}")
            console.print(f"     Sysfs Path:   [dim]{d.sysfs_path}[/dim]")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="rssi",
        description="Wi-Fi RSSI Collector and Monitor for USB Wi-Fi Dongles"
    )
    subparsers = parser.add_subparsers(dest="command", help="Sub-commands")

    # SCAN command
    scan_parser = subparsers.add_parser("scan", help="Perform a one-shot scan of nearby Wi-Fi APs")
    scan_parser.add_argument("-i", "--interface", help="Wireless interface to use (defaults to auto-detected USB dongle)")
    scan_parser.add_argument("-f", "--filter", help="Filter APs by SSID or BSSID (case-insensitive substring)")
    scan_parser.add_argument("-s", "--sort", choices=["signal", "ssid", "channel", "freq"], default="signal", help="Sort order (default: signal)")
    scan_parser.add_argument("--min-rssi", type=float, help="Only show APs with signal >= MIN_RSSI in dBm (e.g. -75)")
    scan_parser.add_argument("--band", choices=["2.4", "5"], help="Filter by Wi-Fi band (2.4 or 5 GHz)")
    scan_parser.add_argument("-l", "--limit", type=int, default=30, help="Maximum number of APs to display (default: 30)")
    scan_parser.add_argument("--cached", action="store_true", help="Use cached kernel scan dump instead of triggering new scan")
    scan_parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    scan_parser.add_argument("--csv", help="Save scan results to a CSV file")

    # MONITOR command
    monitor_parser = subparsers.add_parser("monitor", help="Continuously monitor RSSI values over time")
    monitor_parser.add_argument("-i", "--interface", help="Wireless interface to use")
    monitor_parser.add_argument("--ssid", help="Target SSID to track (e.g. --ssid 'MyNetwork')")
    monitor_parser.add_argument("--bssid", help="Target BSSID to track (e.g. --bssid '80:ea:96:f2:e1:44')")
    monitor_parser.add_argument("-t", "--interval", type=float, default=1.0, help="Scan interval in seconds (default: 1.0)")
    monitor_parser.add_argument("-n", "--count", type=int, help="Number of scans to perform before exiting (default: infinite)")
    monitor_parser.add_argument("-l", "--limit", type=int, help="Limit number of APs shown in general monitor view")
    monitor_parser.add_argument("--csv", help="Log continuous RSSI data to a CSV file")

    # INFO command
    info_parser = subparsers.add_parser("info", help="Display USB Wi-Fi dongle info and network safety status")

    args = parser.parse_args()

    if args.command == "scan":
        run_scan_command(args)
    elif args.command == "monitor":
        run_monitor_command(args)
    elif args.command == "info":
        run_info_command(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
