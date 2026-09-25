import http.cookiejar
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any


class HttpError(RuntimeError):
    pass


@dataclass
class HttpResponse:
    status: int
    headers: dict[str, str]
    body: bytes
    url: str

    @property
    def charset(self) -> str:
        content_type = self.headers.get("Content-Type", "")
        for part in content_type.split(";")[1:]:
            key, _, value = part.strip().partition("=")
            if key.lower() == "charset" and value:
                return value.strip().strip('"').lower()
        return "utf-8"

    @property
    def text(self) -> str:
        try:
            return self.body.decode(self.charset, errors="replace")
        except LookupError:
            return self.body.decode("utf-8", errors="replace")

    def json(self) -> Any:
        try:
            return json.loads(self.body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise HttpError("router returned invalid JSON") from exc


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class HttpSession:
    def __init__(self, base_url: str, timeout: float = 8, verify_tls: bool = True):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.cookie_jar = http.cookiejar.CookieJar()
        context = ssl.create_default_context()
        if not verify_tls:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookie_jar),
            _NoRedirect(),
            urllib.request.HTTPSHandler(context=context),
        )

    def url(self, path: str) -> str:
        if urllib.parse.urlsplit(path).scheme:
            return path
        return f"{self.base_url}/{path.lstrip('/')}"

    def _validated(self, path: str) -> str:
        target = self.url(path)
        scheme = urllib.parse.urlsplit(target).scheme.lower()
        if scheme not in {"http", "https"}:
            raise HttpError(f"refusing to request unsupported URL scheme {scheme!r}")
        return target

    def request(
        self,
        method: str,
        path: str,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
        follow_redirects: bool = False,
    ) -> HttpResponse:
        request_headers = {
            "Connection": "close",
            "User-Agent": "SkybreRouterManager/1.0",
            "Accept": "application/json, text/html;q=0.9, */*;q=0.8",
        }
        if headers:
            request_headers.update(headers)
        request = urllib.request.Request(  # noqa: S310
            self._validated(path),
            data=data,
            headers=request_headers,
            method=method.upper(),
        )
        try:
            with self.opener.open(request, timeout=self.timeout) as response:  # noqa: S310
                result = HttpResponse(
                    status=response.status,
                    headers={key.title(): value for key, value in response.headers.items()},
                    body=response.read(),
                    url=response.geturl(),
                )
        except urllib.error.HTTPError as exc:
            result = HttpResponse(
                status=exc.code,
                headers={key.title(): value for key, value in (exc.headers or {}).items()},
                body=exc.read(),
                url=exc.geturl(),
            )
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise HttpError(f"router request failed: {exc}") from exc
        if follow_redirects and result.status in {301, 302, 303, 307, 308}:
            location = result.headers.get("Location")
            if location:
                return self.request("GET", urllib.parse.urljoin(result.url, location), follow_redirects=False)
        return result
