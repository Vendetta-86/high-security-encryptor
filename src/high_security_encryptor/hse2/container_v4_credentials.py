"""Fixed-shape password slots for the experimental HSE2 v4 candidate."""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from .container_v4_crypto import V4Sealed, open_v4, seal_v4
from .models import HSE2ModelError
from .password_kdf import HSE2_KDF_SALT_SIZE, derive_kek_from_password, normalize_password

V4_CREDENTIAL_SLOT_SIZE = 77
V4_CREDENTIAL_NONCE_SIZE = 12
V4_CREDENTIAL_KEY_SIZE = 32
V4_CREDENTIAL_TAG_SIZE = 16
_PROFILE_IDS = {"compatible": 1, "hardened": 2}
_ID_PROFILES = {value: key for key, value in _PROFILE_IDS.items()}


@dataclass(frozen=True)
class V4CredentialSlot:
    profile_id: int
    salt: bytes
    nonce: bytes
    wrapped_root_key: bytes
    tag: bytes

    def __post_init__(self) -> None:
        if type(self.profile_id) is not int or self.profile_id not in _ID_PROFILES:
            raise HSE2ModelError("invalid v4 credential profile")
        for value, size, label in (
            (self.salt, HSE2_KDF_SALT_SIZE, "salt"),
            (self.nonce, V4_CREDENTIAL_NONCE_SIZE, "nonce"),
            (self.wrapped_root_key, V4_CREDENTIAL_KEY_SIZE, "wrapped root key"),
            (self.tag, V4_CREDENTIAL_TAG_SIZE, "tag"),
        ):
            if not isinstance(value, bytes) or len(value) != size:
                raise HSE2ModelError(f"invalid v4 credential {label} length")

    def to_bytes(self) -> bytes:
        return bytes((self.profile_id,)) + self.salt + self.nonce + self.wrapped_root_key + self.tag

    @classmethod
    def from_bytes(cls, data: bytes) -> "V4CredentialSlot":
        if not isinstance(data, bytes) or len(data) != V4_CREDENTIAL_SLOT_SIZE:
            raise HSE2ModelError("invalid v4 credential slot length")
        return cls(data[0], data[1:17], data[17:29], data[29:61], data[61:77])


def _slot_aad(*, slot: int, capacity_records: int, profile_id: int) -> bytes:
    return (
        f"HSE2:v4:credential:{slot}:{capacity_records}:1048576:67108864:{profile_id}:v1"
    ).encode("ascii")


def _check_capacity(capacity_records: int) -> None:
    if type(capacity_records) is not int or not 2 <= capacity_records <= 65_536 or capacity_records % 2:
        raise HSE2ModelError("invalid v4 record capacity")


def create_v4_credentials(
    password0: str,
    password1: str,
    *,
    capacity_records: int,
    profile_name: str = "compatible",
) -> tuple[tuple[V4CredentialSlot, V4CredentialSlot], tuple[bytes, bytes]]:
    """Create two same-shaped, independently keyed password slots."""

    _check_capacity(capacity_records)
    profile_id = _PROFILE_IDS.get(profile_name)
    if profile_id is None:
        raise HSE2ModelError("v4 supports only compatible or hardened Argon2id")
    # Validate UTF-8 encoding (without normalization) before performing KDF work.
    password_bytes = (normalize_password(password0), normalize_password(password1))
    if password_bytes[0] == password_bytes[1]:
        raise HSE2ModelError("v4 view passwords must differ")
    roots = (secrets.token_bytes(V4_CREDENTIAL_KEY_SIZE), secrets.token_bytes(V4_CREDENTIAL_KEY_SIZE))
    slots: list[V4CredentialSlot] = []
    for slot_index, password in enumerate((password0, password1)):
        salt = secrets.token_bytes(HSE2_KDF_SALT_SIZE)
        nonce = secrets.token_bytes(V4_CREDENTIAL_NONCE_SIZE)
        kek = derive_kek_from_password(password, profile_name=profile_name, salt=salt).kek.value
        sealed = seal_v4(key=kek, nonce=nonce, plaintext=roots[slot_index],
                         aad=_slot_aad(slot=slot_index, capacity_records=capacity_records,
                                       profile_id=profile_id))
        slots.append(V4CredentialSlot(profile_id, salt, nonce, sealed.ciphertext, sealed.tag))
    return (slots[0], slots[1]), roots


def unlock_v4_credentials(
    password: str,
    slots: tuple[V4CredentialSlot, V4CredentialSlot],
    *,
    capacity_records: int,
) -> tuple[int, bytes]:
    """Run both slot KDFs and accept only one matching view credential."""

    _check_capacity(capacity_records)
    if not isinstance(slots, tuple) or len(slots) != 2 or not all(
        isinstance(slot, V4CredentialSlot) for slot in slots
    ):
        raise HSE2ModelError("v4 credential authentication failed")
    if slots[0].profile_id != slots[1].profile_id:
        raise HSE2ModelError("v4 credential authentication failed")
    profile_name = _ID_PROFILES[slots[0].profile_id]
    normalize_password(password)
    matches: list[tuple[int, bytes]] = []
    for slot_index, slot in enumerate(slots):
        kek = derive_kek_from_password(password, profile_name=profile_name, salt=slot.salt).kek.value
        try:
            root = open_v4(
                key=kek,
                sealed=V4Sealed(slot.nonce, slot.wrapped_root_key, slot.tag),
                aad=_slot_aad(slot=slot_index, capacity_records=capacity_records,
                              profile_id=slot.profile_id),
            )
        except HSE2ModelError:
            continue
        if len(root) == V4_CREDENTIAL_KEY_SIZE:
            matches.append((slot_index, root))
    if len(matches) != 1:
        raise HSE2ModelError("v4 credential authentication failed")
    return matches[0]

