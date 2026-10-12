"""
Reverse image search helper: pushes a local image through Google Lens,
Yandex, Bing and TinEye via an anonymous file host (no API key needed).

The search engines can only index images by URL, so the image is first
uploaded to a public host (catbox.moe, tmpfiles.org or 0x0.st), then each
engine is opened in the default browser with the hosted URL embedded.
"""
from __future__ import annotations

import json
import mimetypes
import secrets
import urllib.parse
import urllib.request
import webbrowser
from pathlib import Path

# Engines that accept query-by-hosted-URL (all free, no API key).
ENGINES: tuple[tuple[str, str], ...] = (
    ("Google Lens", "https://lens.google.com/uploadbyurl?url={url}"),
    ("Yandex", "https://yandex.com/images/search?rpt=imageview&url={url}"),
    ("Bing", "https://www.bing.com/images/search?q=imgurl:{url}&view=detailv2&iss=sbi&form=SBIHDR"),
    ("TinEye", "https://tineye.com/search?url={url}"),
)

_UA = "Mozilla/5.0 (ExifEye reverse-image-search)"


class UploadError(RuntimeError):
    """Raised when no anonymous host accepts the image."""


def upload_image(path: Path) -> str:
    """Upload the image to a public host, trying several anonymous hosts."""
    errors: list[str] = []
    for uploader in (_upload_catbox, _upload_tmpfiles, _upload_0x0):
        try:
            return uploader(path)
        except Exception as e:  # try the next host
            errors.append(f"{uploader.__name__}: {e}")
    raise UploadError("every anonymous host refused the upload:\n" + "\n".join(errors))


def open_reverse_search(hosted_url: str) -> list[str]:
    """Open every search engine tab for the hosted image.

    Returns the list of engines successfully opened.
    """
    quoted = urllib.parse.quote(hosted_url, safe="")
    opened: list[str] = []
    for label, template in ENGINES:
        try:
            webbrowser.open_new_tab(template.format(url=quoted))
            opened.append(label)
        except webbrowser.Error:
            continue
    return opened


def _multipart(fields: dict[str, str], file_path: Path,
               file_field: str) -> tuple[bytes, str]:
    """Build a multipart/form-data body with the image file attached."""
    boundary = "----ExifEye" + secrets.token_hex(8)
    chunks: list[bytes] = []
    for key, value in fields.items():
        chunks.append(
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"{key}\"\r\n\r\n"
            f"{value}\r\n".encode()
        )
    mime = mimetypes.guess_type(file_path.name)[0] or "application/octet-stream"
    chunks.append(
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"{file_field}\"; "
        f"filename=\"{file_path.name}\"\r\nContent-Type: {mime}\r\n\r\n".encode()
    )
    chunks.append(file_path.read_bytes())
    chunks.append(f"\r\n--{boundary}--\r\n".encode())
    return b"".join(chunks), f"multipart/form-data; boundary={boundary}"


def _post(url: str, body: bytes, content_type: str, timeout: int = 60) -> bytes:
    request = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": content_type, "User-Agent": _UA},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def _upload_catbox(path: Path) -> str:
    body, ctype = _multipart({"reqtype": "fileupload"}, path, "fileToUpload")
    reply = _post("https://catbox.moe/user/api.php", body, ctype).decode().strip()
    if not reply.startswith("http"):
        raise UploadError(f"catbox refused upload: {reply[:160]}")
    return reply


def _upload_tmpfiles(path: Path) -> str:
    body, ctype = _multipart({}, path, "file")
    reply = _post("https://tmpfiles.org/api/v1/upload", body, ctype)
    url = json.loads(reply)["data"]["url"]
    # tmpfiles returns /<id>/<name>; direct serving lives under /dl/
    if "tmpfiles.org/" in url and "/dl/" not in url:
        url = url.replace("tmpfiles.org/", "tmpfiles.org/dl/", 1)
    return url


def _upload_0x0(path: Path) -> str:
    body, ctype = _multipart({}, path, "file")
    reply = _post("https://0x0.st", body, ctype).decode().strip()
    if not reply.startswith("http"):
        raise UploadError(f"0x0.st refused upload: {reply[:160]}")
    return reply