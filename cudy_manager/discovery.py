import ipaddress
import re
import ssl
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any


@dataclass
class DiscoveredDevice:
    host: str
    vendor: str
    model: str = ""
    firmware: str = ""
    port: int = 80
    markers: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "vendor": self.vendor,
            "model": self.model,
            "firmware": self.firmware,
            "port": self.port,
            "markers": self.markers,
        }


class DiscoveryError(ValueError):
    pass


def _address_key(host: str):
    """Sort numerically for IPv4 and IPv6, falling back to text if unparsable."""
    try:
        return (0, ipaddress.ip_address(host))
    except ValueError:
        return (1, host)


class CudyDiscovery:
    ports = (80, 443, 8080, 3000)

    def __init__(self, subnet: str = "192.168.1.0/24", timeout: float = 0.6):
        self.subnet = self.validate_subnet(subnet)
        self.timeout = timeout
        self.discovered: list[DiscoveredDevice] = []
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context),
        )

    @staticmethod
    def validate_subnet(subnet: str) -> str:
        try:
            network = ipaddress.ip_network(str(subnet), strict=False)
        except ValueError as exc:
            raise DiscoveryError("subnet must be a valid CIDR network") from exc
        if network.num_addresses > 1024:
            raise DiscoveryError("subnet is too large; use a /22 or smaller")
        if network.prefixlen == 0:
            raise DiscoveryError("scanning the entire Internet is not allowed")
        return str(network)

    @staticmethod
    def _url(host: str, port: int, path: str) -> str:
        rendered = f"[{host}]" if ":" in host else host
        # Port 443 is HTTPS. Probing it over plain HTTP means an HTTPS-only router
        # never answers, so the device is silently missed.
        scheme = "https" if port == 443 else "http"
        return f"{scheme}://{rendered}:{port}{path}"

    def _read(self, host: str, port: int, path: str) -> tuple[int, str] | None:
        url = self._url(host, port, path)
        request = urllib.request.Request(  # noqa: S310
            url,
            headers={"User-Agent": "SkybreRouterManager/1.0", "Connection": "close"},
        )
        # Router admin pages almost always use a self-signed certificate, and
        # discovery only reads unauthenticated identity files on the operator's own
        # LAN, so certificate verification is skipped for the HTTPS probe.
        opener = self._opener if url.startswith("https://") else urllib.request.build_opener()
        try:
            with opener.open(request, timeout=self.timeout) as response:  # noqa: S310
                return response.status, response.read(262144).decode(errors="replace")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read(262144).decode(errors="replace")
        except (urllib.error.URLError, TimeoutError, OSError, ssl.SSLError):
            return None

    def _probe(self, host: str) -> DiscoveredDevice | None:
        for port in self.ports:
            identity = self._read(host, port, "/config/macro_config.js")
            if identity:
                status, body = identity
                if status < 500 and "CONFIG_PRODUCT_MODEL" in body:
                    values = dict(re.findall(r"var\s+(\w+)\s*=\s*\"([^\"]*)\"", body))
                    return DiscoveredDevice(
                        host=host,
                        vendor="tenda",
                        model=values.get("CONFIG_PRODUCT_MODEL", "Tenda"),
                        firmware=values.get("CONFIG_FIRMWARE_VERION", ""),
                        port=port,
                        markers=["tenda", "macro_config"],
                    )
            page = self._read(host, port, "/cgi-bin/luci/")
            if page:
                status, body = page
                lowered = body.lower()
                if status < 500 and any(marker in lowered for marker in ("cudy", "luci", "cgi-bin/luci")):
                    model = self._model_from_text(body)
                    return DiscoveredDevice(
                        host=host,
                        vendor="cudy",
                        model=model,
                        port=port,
                        markers=[marker for marker in ("cudy", "luci", "cgi-bin/luci") if marker in lowered],
                    )
        return None

    @staticmethod
    def _model_from_text(body: str) -> str:
        match = re.search(r"(?:model|product)[^A-Za-z0-9]{0,12}([A-Za-z0-9-]{3,})", body, re.IGNORECASE)
        if match:
            return match.group(1)
        title = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
        return " ".join(title.group(1).split()) if title else "Cudy Router"

    def discover(self) -> list[DiscoveredDevice]:
        network = ipaddress.ip_network(self.subnet)
        hosts = [str(host) for host in network.hosts()]
        self.discovered = []
        with ThreadPoolExecutor(max_workers=min(32, max(1, len(hosts)))) as pool:
            futures = {pool.submit(self._probe, host): host for host in hosts}
            for future in as_completed(futures):
                try:
                    device = future.result()
                except (OSError, ValueError):
                    device = None
                if device is not None:
                    self.discovered.append(device)
        self.discovered.sort(key=lambda item: _address_key(item.host))
        return self.discovered

    def arp_scan(self) -> list[dict[str, str]]:
        return [{"ip": device.host, "mac": ""} for device in self.discovered]

    def probe_http(self, ip: str, port: int = 80) -> dict[str, Any] | None:
        result = self._read(ip, port, "/")
        if result is None:
            return None
        status, body = result
        return {
            "status_code": status,
            "title": self._model_from_text(body),
            "is_cudy": "cudy" in body.lower(),
            "is_luci": "luci" in body.lower(),
        }

    def get_http_headers(self, ip: str, port: int = 80) -> dict[str, str] | None:
        request = urllib.request.Request(self._url(ip, port, "/"), method="HEAD")  # noqa: S310
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:  # noqa: S310
                return {key.title(): value for key, value in response.headers.items()}
        except (urllib.error.URLError, TimeoutError, OSError):
            return None


DeviceDiscovery = CudyDiscovery
