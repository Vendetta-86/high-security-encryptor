"""PyInstaller entry point for the HSE2 access CLI executable."""

from high_security_encryptor.hse2_access_cli import main


if __name__ == "__main__":
    raise SystemExit(main())
