# HSE2 Container Format

HSE2 is the planned self-describing file container format for high-security-encryptor. It is designed for offline brute-force resistance, explicit key management, and safer recovery workflows without turning the project into a disk-encryption or hidden-volume system.

## Goals

- Use a random data encryption key instead of encrypting payload data directly with a password-derived key.
- Support multiple independent unlock wrappers such as password, keyfile, password+keyfile, and Windows DPAPI.
- Store KDF parameters in the authenticated container metadata so future files can use stronger profiles without breaking older files.
- Encrypt the manifest by default for hardened and paranoid workflows.
- Support header backup, wrapper rotation, wrapper removal, and explicit access destruction.

## Non-goals

- HSE2 is not a virtual disk format.
- HSE2 does not provide a Windows filesystem driver.
- HSE2 does not claim VeraCrypt-style hidden volume deniability.
- HSE2 does not guarantee secure deletion of plaintext from SSDs, caches, temporary files, logs, backups, or shadow copies.
- HSE2 should not implement an automatic nuke password in the normal unlock path.

## Threat model focus

The main HSE2 attacker model is an offline attacker who has copied the encrypted artifact and can make unlimited password guesses away from the original machine. Local brute-force throttling is useful for interactive misuse, but it does not constrain this attacker.

HSE2 therefore focuses on:

- expensive memory-hard KDF profiles;
- keyfiles or external wrapping secrets that may not be present with the ciphertext;
- local-only wrappers such as DPAPI for convenience rather than sole recovery;
- explicit recovery and destruction controls.

## Logical layout

```text
HSE2 container
├── fixed prelude
│   ├── magic = HSE2
│   ├── format_version = 2
│   └── header_length
├── authenticated header
│   ├── cipher suite
│   ├── KDF profiles
│   ├── manifest policy
│   ├── payload layout
│   └── wrappers[]
├── encrypted manifest
├── encrypted payload chunks
└── footer / final authentication metadata
```

The first implementation may use canonical JSON for the authenticated header to keep the format easy to inspect. A later version can move to CBOR or another deterministic binary encoding if necessary.

## Key hierarchy

```text
DEK = random data encryption key
MEK = random manifest encryption key
KEK = key encryption key derived or obtained from a wrapper provider
```

Payload data is encrypted with DEK. Manifest data is encrypted with MEK. Passwords, keyfiles, DPAPI, and future providers only unwrap DEK and MEK.

```text
password / keyfile / DPAPI
        ↓
KDF or provider-specific unwrap
        ↓
KEK
        ↓
wrapped DEK + wrapped MEK
        ↓
encrypted payload + encrypted manifest
```

## KDF profiles

Initial Argon2id profiles:

| Profile | Memory | Time cost | Parallelism | Use |
|---|---:|---:|---:|---|
| compatible | 64 MiB | 3 | 4 | legacy-compatible and low-memory machines |
| hardened | 256 MiB | 3 | 4 | default for new HSE2 encryption |
| paranoid | 1 GiB | 4 | 4 | high-value, low-frequency cold archives |

The exact parameters must be stored per wrapper, not inferred from application defaults.

## Wrapper types

Initial supported wrapper types:

| Type | Required for first stable HSE2 | Purpose |
|---|---:|---|
| password | yes | baseline password unlock |
| keyfile | yes | separate high-entropy secret for offline resistance |
| password_keyfile | yes | dual-factor unlock path |
| dpapi | yes on Windows | local convenience wrapper bound to a Windows user or machine context |

Future wrapper types such as recovery, command, hardware token, or duress should not be added until the base format is stable.

## Wrapper record

A wrapper record describes how to unlock DEK and MEK. Example logical shape:

```json
{
  "id": "password-1",
  "type": "password",
  "kdf": {
    "algorithm": "argon2id",
    "profile": "hardened",
    "salt": "base64",
    "memory_cost_kib": 262144,
    "time_cost": 3,
    "parallelism": 4
  },
  "wrap_cipher": "AES-256-GCM",
  "nonce": "base64",
  "wrapped_keys": {
    "dek": "base64",
    "mek": "base64"
  },
  "created_utc": "2026-05-25T00:00:00Z",
  "label": "main password"
}
```

## Header backup

Header backup must preserve the authenticated header and wrapper records without storing plaintext DEK, plaintext MEK, passwords, or keyfile material.

Header backup commands should be explicit:

```text
hse2 header export
hse2 header restore
```

## Destroy access

Destroy access is the safe borrowing of the LUKS keyslot destruction idea. It should remove all wrapper records or replace them with a destroyed marker. It should not delete the encrypted payload file and should not claim to securely erase SSD data.

The command must require an explicit confirmation phrase and should strongly recommend an offline header backup before use.

## Duress / decoy policy

A later duress mode may unlock a decoy manifest and decoy payload, but it must not automatically destroy real access in the normal unlock path. Any decoy mode must be documented as metadata reduction and workflow support, not as a full deniability guarantee.
