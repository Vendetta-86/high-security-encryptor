"""Small entry helper for launching the standalone HSE2 GUI from other GUIs."""

from __future__ import annotations

import tkinter as tk

from .hse2_gui_launcher import HSE2ExperimentalApp


def open_hse2_experimental_window(parent: tk.Misc | None = None) -> tk.Toplevel:
    """Open the standalone HSE2 experimental GUI as a child window."""

    window = tk.Toplevel(parent)
    HSE2ExperimentalApp(window)  # type: ignore[arg-type]
    window.transient(parent) if parent is not None else None
    return window
