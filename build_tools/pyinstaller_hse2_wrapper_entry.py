"""PyInstaller entry point for the HSE2 wrapper CLI executable."""

from high_security_encryptor.hse2_wrapper_cli import main


if __name__ == "__main__":
    raise SystemExit(main())
