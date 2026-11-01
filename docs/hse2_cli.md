# Experimental HSE2 CLI Commands

HSE2 CLI commands are explicit experimental entry points. They do not replace the
existing HSE1 batch encryption/decryption workflows.

## Wrapper Input Sources

Each HSE2 command requires exactly one wrapper input source for each wrapper
value it needs.

Supported sources:

- literal argument: `--secret VALUE`, `--old-secret VALUE`, `--new-secret VALUE`;
- environment variable: `--secret-env NAME`, `--old-secret-env NAME`, `--new-secret-env NAME`;
- UTF-8 file: `--secret-file PATH`, `--old-secret-file PATH`, `--new-secret-file PATH`;
- interactive prompt: `--secret-prompt`, `--old-secret-prompt`, `--new-secret-prompt`.

Prefer env, file, or prompt sources. Literal arguments are kept for tests and
quick experiments, but command-line arguments may be visible to local process
inspection tools and shell history.

## Commands

Inspect safe container metadata without decrypting payload content:

```bash
high-security-encryptor hse2 inspect --input <ARCHIVE_PATH>
```

The command prints format, authenticated layout, and wrapper metadata as JSON. It
does not print wrapper bytes or decrypt filenames or payload content.

Add unlock wrappers with explicit factor types:

```bash
high-security-encryptor hse2 wrapper add-password \
  --input <ARCHIVE_PATH> --output <OUTPUT_PATH> --wrapper-id <WRAPPER_ID> \
  --keyfile <CURRENT_KEYFILE> --new-password-file <NEW_PASSWORD_FILE>

high-security-encryptor hse2 wrapper add-keyfile \
  --input <ARCHIVE_PATH> --output <OUTPUT_PATH> --wrapper-id <WRAPPER_ID> \
  --keyfile <CURRENT_KEYFILE> --new-keyfile <NEW_KEYFILE>

high-security-encryptor hse2 wrapper add-dpapi \
  --input <ARCHIVE_PATH> --output <OUTPUT_PATH> --wrapper-id <WRAPPER_ID> \
  --keyfile <CURRENT_KEYFILE>
```

The existing container is unlocked with `--password-file`, `--keyfile`, or
`--dpapi`. Password and keyfile commands also accept the other new factor to
create a combined wrapper. DPAPI is Windows-only; retain an independent password
or keyfile wrapper for recovery.

The same command group can list, remove, or replace a wrapper:

```bash
high-security-encryptor hse2 wrapper list --input <ARCHIVE_PATH>

high-security-encryptor hse2 wrapper remove \
  --input <ARCHIVE_PATH> --output <OUTPUT_PATH> --wrapper-id <WRAPPER_ID> \
  --keyfile <CURRENT_KEYFILE>

high-security-encryptor hse2 wrapper rewrap \
  --input <ARCHIVE_PATH> --output <OUTPUT_PATH> --wrapper-id <OLD_ID> \
  --new-wrapper-id <NEW_ID> --keyfile <CURRENT_KEYFILE> \
  --new-keyfile <NEW_KEYFILE>

high-security-encryptor hse2 access destroy \
  --input <ARCHIVE_PATH> --output <ACCESS_DESTROYED_PATH> \
  --confirm "I UNDERSTAND THIS WILL MAKE THE DATA PERMANENTLY UNRECOVERABLE" \
  --keyfile <CURRENT_KEYFILE>
```

Access destruction always writes a separate output container (unless
`--overwrite` is explicitly selected) and removes every unlock wrapper from it.

Validate a batch of HSE2 containers without creating plaintext output:

```bash
high-security-encryptor hse2 validate --config <VALIDATION_CONFIG_JSON>
```

The unified route accepts `--output`, `--summary-only`, and
`--exit-code-on-failure`, matching the existing `hse2-validate` helper.

### Encrypt one file

```bash
high-security-encryptor hse2-encrypt \
  --input plain.bin \
  --output cipher.hse2 \
  --secret-env HSE2_WRAPPER \
  --kdf-profile hardened
```

Optional arguments:

- `--kdf-profile`: `compatible`, `hardened`, or `paranoid`; defaults to `hardened`.
- `--chunk-size`: payload chunk size in bytes; defaults to 1048576.

### Decrypt one file

```bash
high-security-encryptor hse2-decrypt \
  --input cipher.hse2 \
  --output restored.bin \
  --secret-env HSE2_WRAPPER
```

### Rewrap one file

```bash
high-security-encryptor hse2-rewrap \
  --input cipher.hse2 \
  --output rewrapped.hse2 \
  --old-secret-env CURRENT_HSE2_WRAPPER \
  --new-secret-env REPLACEMENT_HSE2_WRAPPER \
  --new-kdf-profile hardened
```

Rewrap replaces KDF/wrapped-DEK metadata and copies payload bytes unchanged.

## Security Notes

The provider options reduce accidental exposure compared with literal command-line
arguments. They do not remove the need for host security, access control, careful
shell history handling, and protected storage for wrapper files or environment
variables.

## Scope

Implemented:

- explicit single-file HSE2 encryption command;
- explicit single-file HSE2 decryption command;
- explicit single-file HSE2 rewrap command;
- env/file/prompt/literal wrapper input sources;
- JSON summaries that report wrapper source type without echoing the value;
- CLI tests for round trip, provider sources, rewrap, and help visibility.

Not implemented yet:

- batch HSE2 configs;
- GUI integration;
- migration from HSE1 to HSE2;
- making HSE2 the default format.

## Experimental v4 alternate views

The isolated v4 alternate-view feature is available in the Python CLI and the separate HSE2 experimental GUI. The GUI currently accepts one file mapping for each view per operation; the CLI supports repeated mappings. Local malformed-input, capacity/resource-boundary, cleanup, atomic-publication-failure, and official Windows Release ZIP checks are complete; broader fuzz/property testing remains optional follow-up hardening. V4 must not be treated as a plausible-deniability or coercion-safety feature. V2/v3 behavior is unchanged. See [`hse2_phase8_format_proposal.md`](hse2_phase8_format_proposal.md).

Create a two-view container. Passwords are entered through masked prompts and never passed as command-line arguments. Each `ARCHIVE_PATH=SOURCE_PATH` pair maps one input file into that view; repeat the option for additional files. Empty views are allowed.
For redirected automation, `--passwords-stdin` reads exactly four lines (primary password and confirmation, then secondary password and confirmation). The `v4-open` and `v4-replace` commands accept `--password-stdin` for one line. These options reject terminal stdin; otherwise interactive passwords continue to use hidden prompts.

```text
high-security-encryptor hse2 v4-create \
  --output <NEW_CONTAINER> \
  --capacity-records 16 \
  --primary-file docs/main.txt=C:\private\main.txt \
  --secondary-file notes/cover.txt=C:\private\cover.txt
```

The capacity must be even (2 through 65,536), and each view gets half of the fixed record slots. A minimum-capacity container is about 130 MiB because the format reserves two 64 MiB descriptors.

Restore the view selected by one password:

```text
high-security-encryptor hse2 v4-open \
  --input <CONTAINER> \
  --output-dir <NEW_DIRECTORY>
```

Replace one selected view in a new container copy. The peer view and input container are preserved:

```text
high-security-encryptor hse2 v4-replace \
  --input <CONTAINER> \
  --output <NEW_CONTAINER_COPY> \
  --file docs/main.txt=C:\private\updated-main.txt
```

The new output path must differ from the input path. GUI v4 operations ask for explicit confirmation before restore or replacement; credentials stay outside the command line and logs. The fixed-layout format and GUI remain experimental.

## 2026-11-01 Current CLI Status

The earlier scope list above records an older implementation snapshot. The current unified `hse2` command tree includes inspect, validation, wrapper management, explicit access destruction, keyfile operations, and experimental v4 create/open/replace. Dedicated `high-security-encryptor-hse2-*` helper commands cover archive creation/open and related workflows. The v0.7.0 Windows Release ZIP passed the ten-EXE manifest checks and packaged v4 create/open/replace smoke, including preservation of the peer view. See [`releases/v0.7.0.md`](releases/v0.7.0.md) for release evidence.
