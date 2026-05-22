# Main GUI HSE2 Button Wiring Plan

The repository already provides the following HSE2 GUI pieces:

- `high-security-encryptor-hse2-gui`: standalone HSE2 experimental GUI launcher.
- `high_security_encryptor.hse2_gui_tab.HSE2ExperimentalTab`: reusable HSE2 tab component.
- `high_security_encryptor.hse2_gui_entry.open_hse2_experimental_window(...)`: helper for opening the standalone HSE2 window from another GUI.

The remaining main-GUI wiring should be intentionally small: add a visible button
in the existing Tkinter GUI and call the entry helper from its handler.

## Recommended UI Location

Use the existing log-header button row created by `HighSecurityEncryptorApp._build_log(...)`.
That area is always visible, has low layout risk, and already contains utility
buttons such as `清空结果`.

## Intended Patch Shape

Add a button beside the existing log controls:

```python
ttk.Button(button_row, text="打开 HSE2 实验工具", command=self._open_hse2_experimental_gui).pack(
    side=tk.RIGHT,
    padx=(0, 8),
)
```

Add a lazy-import handler inside `HighSecurityEncryptorApp`:

```python
def _open_hse2_experimental_gui(self) -> None:
    from .hse2_gui_entry import open_hse2_experimental_window

    open_hse2_experimental_window(self.master)
```

## Why Lazy Import

The main GUI should not import the HSE2 launcher at module import time. Lazy
import keeps the main GUI startup path unchanged and isolates HSE2 experimental
UI code until the user explicitly opens it.

## Non-goals

The button should not:

- embed the HSE2 tab directly into the main notebook yet;
- duplicate HSE2 workflow logic;
- bypass CLI-based HSE2 execution;
- store wrapper, keyfile, or DPAPI bytes in main-GUI state;
- change HSE1/HSE2 runtime behavior.

## Verification

After the button is wired, CI should verify:

- `python -m compileall -q src tests`
- `python -m unittest discover -s tests`
- `high-security-encryptor-gui --smoke-test`
- `high-security-encryptor-hse2-gui` remains installable through package metadata

A future manual Windows check should open the main GUI, click `打开 HSE2 实验工具`,
and confirm the child HSE2 experimental window appears.
