import argparse
import json
import logging
import shutil
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from scanner.parser import parse_nmap_xml
from scanner.runner import ScanResult, probe_target
from scanner.validator import parse_scope_file


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scope-validated, concurrent Nmap discovery wrapper."
    )
    parser.add_argument(
        "-i", "--input", type=Path, required=True, help="Path to targets file (IPs/CIDRs)"
    )
    parser.add_argument(
        "-e", "--exclude", type=Path, default=None, help="Path to excluded IPs/CIDRs file"
    )
    parser.add_argument(
        "-o", "--output", type=Path, default=Path("scan_results.json"), help="Output JSON path"
    )
    parser.add_argument(
        "-p", "--ports", default="80,443,22", help="Comma-separated ports (default: 80,443,22)"
    )
    parser.add_argument(
        "-t", "--timeout", type=int, default=30, help="Per-target timeout in seconds"
    )
    parser.add_argument(
        "-w", "--workers", type=int, default=5, help="Concurrent worker threads (default: 5)"
    )
    return parser


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    args = build_parser().parse_args()

    # 1. Pre-flight binary check before touching scope or threads
    if shutil.which("nmap") is None:
        logging.critical("Pre-flight check failed: 'nmap' is not installed or not in PATH.")
        return 1

    # 2. Validate and expand scope
    try:
        targets = parse_scope_file(args.input, args.exclude)
    except FileNotFoundError as e:
        logging.critical(str(e))
        return 1

    if not targets:
        logging.warning("No valid targets remaining after scope validation.")
        return 0

    logging.info(f"Starting scan across {len(targets)} valid target(s) with {args.workers} workers...")
    results_report: list[dict] = []

    # 3. Concurrent execution with graceful Ctrl+C handling
    executor = ThreadPoolExecutor(max_workers=args.workers)
    futures = {
        executor.submit(probe_target, ip, args.ports, args.timeout): ip for ip in targets
    }

    try:
        for future in as_completed(futures):
            scan_res: ScanResult = future.result()
            entry = {
                "target": scan_res.target,
                "status": scan_res.status,
                "error": scan_res.error_detail,
            }
            if scan_res.status == "success" and scan_res.raw_xml:
                entry["data"] = parse_nmap_xml(scan_res.raw_xml)

            results_report.append(entry)
            logging.info(f"Completed {scan_res.target} -> {scan_res.status}")

    except KeyboardInterrupt:
        logging.warning("Interrupt received! Cancelling pending scans and saving partial results...")
        executor.shutdown(wait=False, cancel_futures=True)

    finally:
        executor.shutdown(wait=False)
        args.output.write_text(json.dumps(results_report, indent=2), encoding="utf-8")
        logging.info(f"Saved {len(results_report)} records to {args.output}")

    return 0


if __name__ == "__main__":
    sys.exit(main())