# Windows EXE Distribution

The Windows executable is a PyInstaller build of the same CLI exposed by the
Python package. Releases include the command-line executable, the main GUI
executable, and the standalone experimental HSE2 GUI executable.

## Build Locally

Use a supported Python version, preferably the same Python version used by the
release workflow.

```powershell
python -m pip install -e ".[build]"
python -m PyInstaller --clean --noconfirm --onefile --console --name high-security-encryptor --paths src --distpath dist\hse-windows-x64 --workpath build\hse-pyinstaller --specpath build\hse-spec build_tools\pyinstaller_entry.py
python -m PyInstaller --clean --noconfirm --onefile --windowed --name high-security-encryptor-gui --paths src --distpath dist\hse-windows-x64 --workpath build\hse-gui-pyinstaller --specpath build\hse-gui-spec build_tools\pyinstaller_gui_entry.py
python -m PyInstaller --clean --noconfirm --onefile --windowed --name high-security-encryptor-hse2-gui --paths src --distpath dist\hse-windows-x64 --workpath build\hse2-gui-pyinstaller --specpath build\hse2-gui-spec build_tools\pyinstaller_hse2_gui_entry.py
dist\hse-windows-x64\high-security-encryptor.exe --help
dist\hse-windows-x64\high-security-encryptor-gui.exe --smoke-test
```

Double-clicking `high-security-encryptor.exe` shows the CLI help screen. On
Windows interactive consoles, the program waits for Enter before closing so the
help text remains visible.

Double-clicking `high-security-encryptor-gui.exe` opens the Chinese GUI. The GUI
wraps the existing CLI commands for config validation, batch encryption, batch
decryption, removable-storage BitLocker management, and example config
generation. Prompt password providers are blocked in GUI batch workflows because
they can wait on console input; use literal, env, file, or command providers
instead.

Double-clicking `high-security-encryptor-hse2-gui.exe` opens the standalone
experimental HSE2 GUI. It wraps existing HSE2 CLI workflows for config-based
HSE2 encryption, decryption, validation, keyfile rotation, keyfile generation,
and Windows DPAPI protection. It does not reimplement HSE2 cryptographic logic in
the GUI layer.

## Release Asset

The GitHub Actions workflow builds a zip asset named:

```text
high-security-encryptor-<tag>-windows-x64.zip
```

The zip contains:

- `high-security-encryptor.exe`
- `high-security-encryptor-gui.exe`
- `high-security-encryptor-hse2-gui.exe`
- `README.md`
- this Windows executable note

## Security Notes

The executable does not embed passwords, keys, default secrets, or user config
files. It only packages the Python runtime, project code, and runtime
dependencies needed by the CLI and GUI launchers.

Unsigned Windows executables may trigger browser, SmartScreen, or antivirus
warnings. Code signing can be added later if the project needs broad public
distribution.
