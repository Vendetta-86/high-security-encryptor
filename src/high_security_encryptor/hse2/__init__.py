"""HSE2 container model helpers."""

from .keys import (
    HSE2_KEY_SIZE,
    HSE2KeyMaterial,
    generate_dek,
    generate_kek,
    generate_key_material,
    generate_mek,
    validate_key_bytes,
)
from .models import (
    CipherSuite,
    HSE2Header,
    HSE2ModelError,
    KDFProfile,
    ManifestPolicy,
    PayloadLayout,
    WrappedKeys,
    WrapperRecord,
    canonical_json_bytes,
    get_kdf_profile,
)
from .wrapping import (
    HSE2_WRAP_AUTH_TAG_SIZE,
    HSE2_WRAP_NONCE_SIZE,
    WrappedKeyBlob,
    key_confirmation_tag,
    unwrap_key_material,
    wrap_key_material,
)

__all__ = [
    "CipherSuite",
    "HSE2Header",
    "HSE2ModelError",
    "HSE2KeyMaterial",
    "HSE2_KEY_SIZE",
    "HSE2_WRAP_AUTH_TAG_SIZE",
    "HSE2_WRAP_NONCE_SIZE",
    "KDFProfile",
    "ManifestPolicy",
    "PayloadLayout",
    "WrappedKeyBlob",
    "WrappedKeys",
    "WrapperRecord",
    "canonical_json_bytes",
    "generate_dek",
    "generate_kek",
    "generate_key_material",
    "generate_mek",
    "get_kdf_profile",
    "key_confirmation_tag",
    "unwrap_key_material",
    "validate_key_bytes",
    "wrap_key_material",
]
