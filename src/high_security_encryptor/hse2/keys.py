"""Random key generation primitives for HSE2."""

from __future__ import annotations

from dataclasses import dataclass
import secrets

from .constants import AES_256_KEY_BYTES, GCM_NONCE_BYTES
from .errors import HSE2KeyError


@dataclass(frozen=True, slots=True)
class KeyBundle:
    """Random per-container keys used by the HSE2 encryption pipeline."""

    dek: bytes
    mek: bytes
    payload_nonce_seed: bytes
    manifest_nonce: bytes

    def validate(self) -> None:
        """Validate key and nonce lengths before use."""

        if len(self.dek) != AES_256_KEY_BYTES:
            raise HSE2KeyError("Invalid HSE2 DEK length")
        if len(self.mek) != AES_256_KEY_BYTES:
            raise HSE2KeyError("Invalid HSE2 MEK length")
        if len(self.payload_nonce_seed) != AES_256_KEY_BYTES:
            raise HSE2KeyError("Invalid HSE2 payload nonce seed length")
        if len(self.manifest_nonce) != GCM_NONCE_BYTES:
            raise HSE2KeyError("Invalid HSE2 manifest nonce length")


def generate_key_bundle() -> KeyBundle:
    """Generate fresh random HSE2 container keys.

    Passwords and wrapper providers must never be used directly as payload keys.
    They only wrap this randomly generated key bundle.
    """

    bundle = KeyBundle(
        dek=secrets.token_bytes(AES_256_KEY_BYTES),
        mek=secrets.token_bytes(AES_256_KEY_BYTES),
        payload_nonce_seed=secrets.token_bytes(AES_256_KEY_BYTES),
        manifest_nonce=secrets.token_bytes(GCM_NONCE_BYTES),
    )
    bundle.validate()
    return bundle
