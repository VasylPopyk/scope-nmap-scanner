import ipaddress
import logging
from pathlib import Path

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def parse_scope_file(
    targets_path: Path,
    exclude_path: Path | None = None,
    rejected_log: Path = Path("rejected_scope.log"),
) -> list[str]:
    """
    Reads raw IPs/CIDRs, removes excluded targets, quarantines malformed lines
    (ValueError), and returns a sorted, deduplicated list of valid IP strings.
    """
    if not targets_path.is_file():
        raise FileNotFoundError(f"Targets file not found: {targets_path}")

    excluded_networks: list[IPNetwork] = []
    if exclude_path:
        if not exclude_path.is_file():
            raise FileNotFoundError(f"Exclusions file not found: {exclude_path}")
        excluded_networks = _load_networks(exclude_path, rejected_log)

    valid_ips: set[IPAddress] = set()
    rejected_lines: list[str] = []

    for line_num, raw_line in enumerate(
        targets_path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        entry = raw_line.strip()
        if not entry or entry.startswith("#"):
            continue

        try:
            # strict=False allows host bits in CIDRs (e.g., 192.168.1.5/24)
            network = ipaddress.ip_network(entry, strict=False)
            if network.num_addresses == 1:
                candidates = [network.network_address]
            else:
                candidates = list(network.hosts())

            for ip in candidates:
                if not any(ip in ex_net for ex_net in excluded_networks):
                    valid_ips.add(ip)

        except ValueError:
            logging.warning(f"Quarantined invalid target (line {line_num}): {entry!r}")
            rejected_lines.append(f"Line {line_num}: {entry}")

    if rejected_lines:
        rejected_log.write_text("\n".join(rejected_lines) + "\n", encoding="utf-8")
        logging.info(f"Wrote {len(rejected_lines)} malformed entries to {rejected_log}")

    return [str(ip) for ip in sorted(valid_ips, key=lambda ip: (ip.version, ip))]


def _load_networks(path: Path, rejected_log: Path) -> list[IPNetwork]:
    networks: list[IPNetwork] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        entry = raw_line.strip()
        if not entry or entry.startswith("#"):
            continue
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            logging.warning(f"Ignoring invalid exclusion entry: {entry!r}")
    return networks