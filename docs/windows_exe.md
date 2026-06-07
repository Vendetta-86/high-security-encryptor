# Windows EXE Distribution

The Windows executable is a PyInstaller build of the same CLI exposed by the Python package. Releases include the command-line executable, the main GUI executable, and the standalone experimental HSE2 GUI executable.

## Build Locally

Use a supported Python version, preferably the same Python version used by the release workflow.

```powershell
python -m pip install -e ".[build]"
python -m PyInstaller --clean --noconfirm --onefile --console --name high-security-encryptor --paths src --distpath dist\hse-windows-x64 --workpath build\hse-pyinstaller --specpath build\hse-spec build_tools\pyinstaller_entry.py
python -m PyInstaller --clean --noconfirm --onefile --windowed --name high-security-encryptor-gui --paths src --distpath dist\hse-windows-x64 --workpath build\hse-gui-pyinstaller --specpath build\hse-gui-spec build_tools\pyinstaller_gui_entry.py
python -m PyInstaller --clean --noconfirm --onefile --windowed --name high-security-encryptor-hse2-gui --paths src --distpath dist\hse-windows-x64 --workpath build\hse2-gui-pyinstaller --specpath build\hse2-gui-spec build_tools\pyinstaller_hse2_gui_entry.py
dist\hse-windows-x64\high-security-encryptor.exe --help
dist\hse-windows-x64\high-security-encryptor-gui.exe --smoke-test
```

## Release Asset

The GitHub Actions workflow builds a zip asset named:

```text
high-security-encryptor-<tag>-windows-x64.zip
```

For release tag `v0.6.0-alpha.1`, the expected asset name is:

```text
high-security-encryptor-v0.6.0-alpha.1-windows-x64.zip
```

The Python package version for this release line is `0.6.0a1`.

The zip should contain:

- `high-security-encryptor.exe`
- `high-security-encryptor-gui.exe`
- `high-security-encryptor-hse2-gui.exe`
- `README.md`
- `windows_exe.md`

## Release Verification

Before publishing or announcing the Windows zip:

- confirm the workflow ran against the intended tag;
- confirm all three executables listed above are present;
- run `high-security-encryptor.exe --help`;
- run `high-security-encryptor-gui.exe --smoke-test`;
- confirm `high-security-encryptor-hse2-gui.exe` exists in the extracted zip;
- confirm the extracted zip only contains intended release files and bundled examples.

## Distribution Notes

Unsigned Windows executables may trigger browser, SmartScreen, or antivirus warnings. Code signing can be added later if the project needs broad public distribution.
