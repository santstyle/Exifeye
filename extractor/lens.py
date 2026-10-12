"""
Private, local-only reverse image search helper.

ExifEye NEVER uploads the image anywhere - no third-party hosts, no Google
staging, no network transfer of the picture at all. `--lens` opens the local
file in the default browser and leaves the Google Lens tab ready; the single
user action is right-click the image -> "Search image with Google" (Chrome /
Edge). That one click sends the picture straight to Google Lens through the
user's own browser - nothing leaves the machine automatically.
"""
from __future__ import annotations

import webbrowser
from pathlib import Path

_LENS_HOME = "https://lens.google.com/"


def open_for_lens(path: Path) -> bool:
    """Open the local image plus a ready Google Lens tab in the browser.

    Returns True when the image tab was opened.
    """
    try:
        opened = webbrowser.open_new_tab(path.resolve().as_uri())
        webbrowser.open_new_tab(_LENS_HOME)
        return bool(opened)
    except webbrowser.Error:
        return False