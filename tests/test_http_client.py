import pytest

from cudy_manager.http_client import HttpError, HttpResponse, HttpSession


def response(body: str, content_type: str = "text/html; charset=utf-8", raw: bytes | None = None) -> HttpResponse:
    return HttpResponse(
        status=200,
        headers={"Content-Type": content_type},
        body=raw if raw is not None else body.encode(),
        url="http://192.168.1.1/",
    )


class TestCharsetHandling:
    def test_html_charset_is_not_used_as_codec(self):
        parsed = response("<html><body>hi</body></html>", "text/html; charset=utf-8")
        assert parsed.text == "<html><body>hi</body></html>"

    def test_plain_text_content_type(self):
        assert response("plain", "text/plain").text == "plain"

    def test_declared_charset_is_honoured(self):
        parsed = response("olá", "text/html; charset=latin-1", raw="olá".encode("latin-1"))
        assert parsed.text == "olá"

    def test_quoted_charset(self):
        assert response("ok", 'text/html; charset="utf-8"').text == "ok"

    def test_invalid_charset_falls_back(self):
        assert response("ok", "text/html; charset=not-a-codec").text == "ok"

    def test_json_decoding(self):
        assert response('{"a": 1}', "application/json").json() == {"a": 1}

    def test_invalid_json_raises(self):
        with pytest.raises(HttpError):
            response("not json", "application/json").json()


class TestUrlValidation:
    def test_relative_paths_are_joined_to_base(self):
        session = HttpSession("http://192.168.1.1:8080")
        assert session.url("/cgi-bin/luci/") == "http://192.168.1.1:8080/cgi-bin/luci/"
        assert session.url("cgi-bin/luci/") == "http://192.168.1.1:8080/cgi-bin/luci/"

    def test_absolute_http_urls_pass_through(self):
        session = HttpSession("http://192.168.1.1:8080")
        assert session.url("http://other/") == "http://other/"

    def test_file_scheme_is_rejected(self):
        session = HttpSession("http://192.168.1.1:8080")
        with pytest.raises(HttpError):
            session.request("GET", "file:///etc/passwd")

    def test_ftp_scheme_is_rejected(self):
        session = HttpSession("http://192.168.1.1:8080")
        with pytest.raises(HttpError):
            session.request("GET", "ftp://example.com/secret")

    def test_base_url_scheme_is_validated(self):
        session = HttpSession("file:///tmp")
        with pytest.raises(HttpError):
            session.request("GET", "/etc/passwd")
