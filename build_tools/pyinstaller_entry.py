"""PyInstaller entry point for the Windows executable."""

from high_security_encryptor.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
