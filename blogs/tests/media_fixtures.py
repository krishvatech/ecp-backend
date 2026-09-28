"""Tiny generated images and a fake HTTP/DNS layer for media tests (no internet)."""
import io
import socket

import requests
from PIL import Image

PUBLIC_IP = "93.184.216.34"


def image_bytes(fmt="PNG", size=(4, 3), color=(10, 147, 150)):
    buffer = io.BytesIO()
    Image.new("RGB", size, color).save(buffer, format=fmt)
    return buffer.getvalue()


def resolver_for(mapping=None, default=PUBLIC_IP):
    """getaddrinfo stand-in: host -> IP (default public)."""
    mapping = mapping or {}

    def resolve(host, port, proto=0, **kwargs):
        ip = mapping.get(host, default)
        if ip is None:
            raise socket.gaierror("unknown host")
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        return [(family, socket.SOCK_STREAM, proto, "", (ip, port))]

    return resolve


class FakeMediaResponse:
    def __init__(self, status=200, body=b"", headers=None):
        self.status_code = status
        self._body = body
        self.headers = requests.structures.CaseInsensitiveDict(headers or {})
        self.closed = False

    def iter_content(self, chunk_size):
        for start in range(0, len(self._body), chunk_size):
            yield self._body[start : start + chunk_size]

    def close(self):
        self.closed = True


class FakeMediaSession:
    """url -> FakeMediaResponse | Exception. Records every requested URL."""

    def __init__(self, routes=None):
        self.routes = dict(routes or {})
        self.requested = []

    def get(self, url, stream=False, allow_redirects=True, timeout=None, headers=None):
        assert stream and not allow_redirects, "media downloads must stream and never auto-follow redirects"
        self.requested.append(url)
        route = self.routes.get(url)
        if route is None:
            return FakeMediaResponse(404, b"not found")
        if isinstance(route, Exception):
            raise route
        return route
