import logging
import subprocess
from dataclasses import dataclass


@dataclass
class ScanResult:
    target: str
    status: str  # "success" | "timeout" | "error"
    raw_xml: str | None = None
    error_detail: str | None = None


def probe_target(target_ip: str, ports: str = "80,443", timeout: int = 30) -> ScanResult:
    """
    Runs an Nmap service scan against a single target IP and captures XML stdout.
    """
    cmd = ["nmap", "-sV", "-Pn", "-p", ports, "-oX", "-", target_ip]

    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=True,
        )
        return ScanResult(target=target_ip, status="success", raw_xml=completed.stdout)

    except FileNotFoundError:
        logging.critical("Nmap binary not found in PATH. Aborting.")
        raise

    except PermissionError:
        logging.critical("Insufficient privileges for requested Nmap flags. Aborting.")
        raise

    except subprocess.TimeoutExpired:
        logging.error(f"[{target_ip}] Scan timed out after {timeout}s")
        return ScanResult(
            target=target_ip,
            status="timeout",
            error_detail=f"Exceeded {timeout}s timeout",
        )

    except subprocess.CalledProcessError as e:
        err_msg = e.stderr.strip() or f"Exit code {e.returncode}"
        logging.error(f"[{target_ip}] Nmap failed: {err_msg}")
        return ScanResult(target=target_ip, status="error", error_detail=err_msg)

    except OSError as e:
        logging.error(f"[{target_ip}] OS/Socket failure: {e.strerror}")
        return ScanResult(target=target_ip, status="error", error_detail=str(e))