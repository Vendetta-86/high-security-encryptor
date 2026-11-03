# Windows EXE Distribution

The Windows executable is a PyInstaller build of the same CLI exposed by the Python package. Releases include the command-line executable, the main GUI executable, the standalone HSE2 GUI executable, and focused HSE2 helper CLI executables, including full archive validation.

## Build Locally

Use a supported Python version, preferably the same Python version used by the release workflow.

```powershell
python -m pip install -e ".[build]"
python -m PyInstaller --clean --noconfirm --onefile --console --name high-security-encryptor --paths src --distpath dist\hse-windows-x64 --workpath build\hse-pyinstaller --specpath build\hse-spec build_tools\pyinstaller_entry.py
python -m PyInstaller --clean --noconfirm --onefile --windowed --name high-security-encryptor-gui --paths src --distpath dist\hse-windows-x64 --workpath build\hse-gui-pyinstaller --specpath build\hse-gui-spec build_tools\pyinstaller_gui_entry.py
python -m PyInstaller --clean --noconfirm --onefile --windowed --name high-security-encryptor-hse2-gui --paths src --distpath dist\hse-windows-x64 --workpath build\hse2-gui-pyinstaller --specpath build\hse2-gui-spec build_tools\pyinstaller_hse2_gui_entry.py
python -m PyInstaller --clean --noconfirm --onefile --console --name high-security-encryptor-hse2-inspect --paths src --distpath dist\hse-windows-x64 --workpath build\hse2-inspect-pyinstaller --specpath build\hse2-inspect-spec build_tools\pyinstaller_hse2_inspect_entry.py
python -m PyInstaller --clean --noconfirm --onefile --console --name high-security-encryptor-hse2-archive-validate --paths src --distpath dist\hse-windows-x64 --workpath build\hse2-archive-validate-pyinstaller --specpath build\hse2-archive-validate-spec build_tools\pyinstaller_hse2_archive_validate_entry.py
dist\hse-windows-x64\high-security-encryptor.exe --help
dist\hse-windows-x64\high-security-encryptor-gui.exe --smoke-test
dist\hse-windows-x64\high-security-encryptor-hse2-inspect.exe --help
dist\hse-windows-x64\high-security-encryptor-hse2-archive-validate.exe --help
```

## Release Asset

The GitHub Actions workflow builds a zip asset named:

```text
high-security-encryptor-<tag>-windows-x64.zip
```

For release tag `v0.6.0-alpha.8`, the expected asset name is:

```text
high-security-encryptor-v0.6.0-alpha.8-windows-x64.zip
```

The Python package version for this release line is `0.6.0a8`.

The `Windows EXE` workflow is safe to run as a build-only check: `publish_release` defaults to `false`, and push-to-tag runs only upload a workflow artifact. To publish, dispatch the workflow from the exact release tag and set `publish_release` to `true`; the publish job verifies the selected ref and tag match, downloads the successfully built artifact, and then creates or updates the GitHub Release. A manual dispatch from a branch cannot publish.

The zip should contain:

- `high-security-encryptor.exe`
- `high-security-encryptor-gui.exe`
- `high-security-encryptor-hse2-gui.exe`
- `high-security-encryptor-hse2-create.exe`
- `high-security-encryptor-hse2-open.exe`
- `high-security-encryptor-hse2-header-backup.exe`
- `high-security-encryptor-hse2-inspect.exe`
- `high-security-encryptor-hse2-archive-validate.exe`
- `high-security-encryptor-hse2-wrapper.exe`
- `high-security-encryptor-hse2-access.exe`
- `README.md`
- `windows_exe.md`

## Release Verification

The beginner materials in the zip start at docs/beginner/README.md and include first-run and batch exercises, a glossary, GUI reference, HSE2 CLI workflow reference, and the phase 3 feature inventory. Read the exercises with disposable sample data before using valuable files.

The v5 GUI practice is docs/beginner/v5-practice.md. It covers create, per-view verification, preview, and restore using isolated sample files; v5 remains experimental and does not provide deniability.

Before publishing or announcing the Windows zip:

- confirm the build-only workflow artifact was produced from the intended tag and contains the expected zip;
- for publication, dispatch the workflow from that exact tag with `publish_release=true`; verify the Release asset after the publish job completes;
- confirm all executables listed above are present;
- run `high-security-encryptor.exe --help`;
- run `high-security-encryptor-gui.exe --smoke-test`;
- run `high-security-encryptor-hse2-gui.exe --smoke-test`;
- confirm the build workflow exercised packaged v4 create, primary/secondary restore, and single-view replacement with byte-for-byte comparisons;
- run `high-security-encryptor.exe hse2 v4-create --help`, `v4-open --help`, and `v4-replace --help`;
- run each HSE2 helper executable with `--help`;
- run `high-security-encryptor-hse2-inspect.exe --help`;
- run `high-security-encryptor-hse2-archive-validate.exe --help`;
- run `high-security-encryptor-hse2-gui.exe` and confirm the localized `检查 HSE2 元数据` action prints raw JSON plus a metadata-only result summary;
- in `high-security-encryptor-hse2-gui.exe`, switch through the localized HSE2 action dropdown and confirm fields hide/show according to the selected action;
- confirm the extracted zip only contains intended release files and bundled examples.

## Distribution Notes

Unsigned Windows executables may trigger browser, SmartScreen, or antivirus warnings. Code signing can be added later if the project needs broad public distribution.
