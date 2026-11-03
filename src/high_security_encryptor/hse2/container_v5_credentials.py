"""Fixed-shape password slots for independently keyed v5 alternate views."""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from .container_v5_crypto import V5Sealed, open_v5, seal_v5
from .models import HSE2ModelError
from .password_kdf import HSE2_KDF_SALT_SIZE, derive_kek_from_password, normalize_password

V5_CREDENTIAL_SLOT_SIZE = 77
V5_CREDENTIAL_NONCE_SIZE = 12
V5_CREDENTIAL_KEY_SIZE = 32
V5_CREDENTIAL_TAG_SIZE = 16
_PROFILE_IDS = {"compatible": 1, "hardened": 2}
_ID_PROFILES = {value: key for key, value in _PROFILE_IDS.items()}


@dataclass(frozen=True)
class V5CredentialSlot:
    profile_id: int
    salt: bytes
    nonce: bytes
    wrapped_root_key: bytes
    tag: bytes

    def __post_init__(self) -> None:
        if type(self.profile_id) is not int or self.profile_id not in _ID_PROFILES:
            raise HSE2ModelError("invalid v5 credential profile")
        for value, size, label in ((self.salt, 16, "salt"), (self.nonce, 12, "nonce"),
                                   (self.wrapped_root_key, 32, "wrapped root key"),
                                   (self.tag, 16, "tag")):
            if not isinstance(value, bytes) or len(value) != size:
                raise HSE2ModelError(f"invalid v5 credential {label} length")

    def to_bytes(self) -> bytes:
        return bytes((self.profile_id,)) + self.salt + self.nonce + self.wrapped_root_key + self.tag

    @classmethod
    def from_bytes(cls, data: bytes) -> "V5CredentialSlot":
        if not isinstance(data, bytes) or len(data) != V5_CREDENTIAL_SLOT_SIZE:
            raise HSE2ModelError("invalid v5 credential slot length")
        return cls(data[0], data[1:17], data[17:29], data[29:61], data[61:77])


def _slot_aad(archive_id: bytes, slot: int, profile_id: int) -> bytes:
    if not isinstance(archive_id, bytes) or len(archive_id) != 16 or type(slot) is not int or slot not in (0, 1):
        raise HSE2ModelError("invalid v5 credential location")
    return f"HSE2:v5:credential:{archive_id.hex()}:{slot}:{profile_id}:v1".encode("ascii")


def wrap_v5_root_key(
    password: str, root_key: bytes, *, archive_id: bytes, slot: int, profile_id: int,
) -> V5CredentialSlot:
    """Create a fresh credential slot wrapping an existing v5 view root key."""

    profile_name = _ID_PROFILES.get(profile_id)
    if profile_name is None or not isinstance(root_key, bytes) or len(root_key) != V5_CREDENTIAL_KEY_SIZE:
        raise HSE2ModelError("invalid v5 credential wrapping input")
    normalize_password(password)
    salt = secrets.token_bytes(HSE2_KDF_SALT_SIZE)
    nonce = secrets.token_bytes(V5_CREDENTIAL_NONCE_SIZE)
    kek = derive_kek_from_password(password, profile_name=profile_name, salt=salt).kek.value
    sealed = seal_v5(key=kek, nonce=nonce, plaintext=root_key,
                     aad=_slot_aad(archive_id, slot, profile_id))
    return V5CredentialSlot(profile_id, salt, nonce, sealed.ciphertext, sealed.tag)


def create_v5_credentials(
    password0: str, password1: str, *, archive_id: bytes, profile_name: str = "compatible",
) -> tuple[tuple[V5CredentialSlot, V5CredentialSlot], tuple[bytes, bytes]]:
    if not isinstance(archive_id, bytes) or len(archive_id) != 16:
        raise HSE2ModelError("v5 archive id must be 16 bytes")
    profile_id = _PROFILE_IDS.get(profile_name)
    if profile_id is None:
        raise HSE2ModelError("v5 supports only compatible or hardened Argon2id")
    if normalize_password(password0) == normalize_password(password1):
        raise HSE2ModelError("v5 view passwords must differ")
    roots = (secrets.token_bytes(32), secrets.token_bytes(32))
    slots = []
    for index, password in enumerate((password0, password1)):
        slots.append(wrap_v5_root_key(
            password, roots[index], archive_id=archive_id, slot=index, profile_id=profile_id,
        ))
    return (slots[0], slots[1]), roots


def unlock_v5_credentials(
    password: str, slots: tuple[V5CredentialSlot, V5CredentialSlot], *, archive_id: bytes,
) -> tuple[int, bytes]:
    if (not isinstance(slots, tuple) or len(slots) != 2
            or not all(isinstance(slot, V5CredentialSlot) for slot in slots)
            or slots[0].profile_id != slots[1].profile_id
            or slots[0].profile_id not in _ID_PROFILES):
        raise HSE2ModelError("v5 credential authentication failed")
    if not isinstance(archive_id, bytes) or len(archive_id) != 16:
        raise HSE2ModelError("v5 credential authentication failed")
    profile_name = _ID_PROFILES[slots[0].profile_id]
    normalize_password(password)
    matches = []
    for index, slot in enumerate(slots):
        kek = derive_kek_from_password(password, profile_name=profile_name, salt=slot.salt).kek.value
        try:
            root = open_v5(key=kek, sealed=V5Sealed(slot.nonce, slot.wrapped_root_key, slot.tag),
                           aad=_slot_aad(archive_id, index, slot.profile_id))
        except HSE2ModelError:
            continue
        if len(root) == V5_CREDENTIAL_KEY_SIZE:
            matches.append((index, root))
    if len(matches) != 1:
        raise HSE2ModelError("v5 credential authentication failed")
    return matches[0]
