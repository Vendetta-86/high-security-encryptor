"""HSE2 container model helpers."""

from .encoding import b64decode_bytes, b64encode_bytes
from .keyfile_kdf import (
    HSE2_KEYFILE_CONTEXT,
    HSE2_KEYFILE_MIN_SIZE,
    KeyfileKDFResult,
    derive_kek_from_keyfile,
    validate_keyfile_bytes,
)
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
from .password_kdf import (
    HSE2_KDF_SALT_SIZE,
    PasswordKDFResult,
    derive_kek_from_password,
    normalize_password,
)
from .wrapper_serialization import (
    WrappedKeyPairBlobs,
    build_wrapper_record,
    wrapped_blob_from_metadata,
    wrapped_blob_to_metadata,
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
    "HSE2_KEYFILE_CONTEXT",
    "HSE2_KEYFILE_MIN_SIZE",
    "HSE2_KEY_SIZE",
    "HSE2_KDF_SALT_SIZE",
    "HSE2_WRAP_AUTH_TAG_SIZE",
    "HSE2_WRAP_NONCE_SIZE",
    "KDFProfile",
    "KeyfileKDFResult",
    "ManifestPolicy",
    "PasswordKDFResult",
    "PayloadLayout",
    "WrappedKeyBlob",
    "WrappedKeyPairBlobs",
    "WrappedKeys",
    "WrapperRecord",
    "b64decode_bytes",
    "b64encode_bytes",
    "build_wrapper_record",
    "canonical_json_bytes",
    "derive_kek_from_keyfile",
    "derive_kek_from_password",
    "generate_dek",
    "generate_kek",
    "generate_key_material",
    "generate_mek",
    "get_kdf_profile",
    "key_confirmation_tag",
    "normalize_password",
    "unwrap_key_material",
    "validate_key_bytes",
    "validate_keyfile_bytes",
    "wrap_key_material",
    "wrapped_blob_from_metadata",
    "wrapped_blob_to_metadata",
]
