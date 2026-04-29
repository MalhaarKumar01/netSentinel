from __future__ import annotations

import argparse
import time

from netsentinel import NetSentinelMonitor, Settings


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the NetSentinel monitor.")
    parser.add_argument(
        "--mode",
        choices=["live", "synthetic"],
        default=None,
        help="Override packet capture mode.",
    )
    parser.add_argument(
        "--window-seconds",
        type=int,
        default=None,
        help="Override the flow aggregation window size.",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    settings = Settings()
    if args.mode:
        settings.capture_mode = args.mode
    if args.window_seconds:
        settings.window_seconds = args.window_seconds

    monitor = NetSentinelMonitor(settings)
    monitor.start()
    print(f"NetSentinel started in {settings.capture_mode} mode. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        monitor.stop()
        print("NetSentinel stopped.")


if __name__ == "__main__":
    main()
