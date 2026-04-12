# Windows EXE Distribution

The Windows executable is a PyInstaller build of the same CLI exposed by the
Python package.

## Build Locally

Use a supported Python version, preferably the same Python version used by the
release workflow.

```powershell
python -m pip install -e ".[build]"
python -m PyInstaller --clean --noconfirm --onefile --console --name high-security-encryptor --paths src --distpath dist\hse-windows-x64 --workpath build\hse-pyinstaller --specpath build\hse-spec build_tools\pyinstaller_entry.py
dist\hse-windows-x64\high-security-encryptor.exe --help
```

Double-clicking `high-security-encryptor.exe` shows the CLI help screen. On
Windows interactive consoles, the program waits for Enter before closing so the
help text remains visible.

## Release Asset

The GitHub Actions workflow builds a zip asset named:

```text
high-security-encryptor-<tag>-windows-x64.zip
```

The zip contains:

- `high-security-encryptor.exe`
- `README.md`
- this Windows executable note

## Security Notes

The executable does not embed passwords, keys, default secrets, or user config
files. It only packages the Python runtime, project code, and runtime
dependencies needed by the CLI.

Unsigned Windows executables may trigger browser, SmartScreen, or antivirus
warnings. Code signing can be added later if the project needs broad public
distribution.
