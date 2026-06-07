"""PyInstaller entry point for the HSE2 header backup CLI executable."""

from high_security_encryptor.hse2_header_backup_cli import main


if __name__ == "__main__":
    raise SystemExit(main())
