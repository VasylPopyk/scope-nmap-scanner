import xml.etree.ElementTree as ET
from typing import Any


def parse_nmap_xml(xml_data: str) -> dict[str, Any]:
    """
    Extracts host status and open/filtered port metadata from Nmap XML output.
    """
    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError as e:
        return {"parse_error": f"Malformed XML output: {e}", "ports": []}

    host_elem = root.find("host")
    if host_elem is None:
        return {"host_state": "down", "ports": []}

    status_elem = host_elem.find("status")
    host_state = status_elem.get("state", "unknown") if status_elem is not None else "unknown"

    ports_data: list[dict[str, str]] = []
    for port_elem in host_elem.findall(".//port"):
        state_elem = port_elem.find("state")
        service_elem = port_elem.find("service")

        ports_data.append(
            {
                "port": port_elem.get("portid", ""),
                "protocol": port_elem.get("protocol", ""),
                "state": state_elem.get("state", "") if state_elem is not None else "",
                "service": service_elem.get("name", "") if service_elem is not None else "",
                "product": service_elem.get("product", "") if service_elem is not None else "",
                "version": service_elem.get("version", "") if service_elem is not None else "",
            }
        )

    return {"host_state": host_state, "ports": ports_data}