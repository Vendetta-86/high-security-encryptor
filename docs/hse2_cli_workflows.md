# HSE2 CLI Workflows

HSE2 remains an explicit experimental workflow, but the core archive lifecycle is now available through focused CLI entry points. These commands do not prompt for secrets and do not store plaintext key material in summaries.

The path values below are placeholders. Replace angle-bracketed values with local test files when running the commands.

## Create and Open

Create a portable keyfile-backed archive:

```bash
high-security-encryptor-hse2-create \
  --root <ROOT_PATH> \
  --output <ARCHIVE_PATH> \
  --keyfile <KEYFILE_PATH>  # pragma: allowlist secret
```

Open it later with the matching keyfile:

```bash
high-security-encryptor-hse2-open \
  --input <ARCHIVE_PATH> \
  --output-dir <RESTORE_DIR> \
  --keyfile <KEYFILE_PATH>  # pragma: allowlist secret
```

For passphrase-file backed workflows, pass a UTF-8 file containing the passphrase. One trailing newline is stripped by the CLI:

```bash
high-security-encryptor-hse2-create \
  --root <ROOT_PATH> \
  --output <ARCHIVE_PATH> \
  --password-file <PASSPHRASE_FILE_PATH>  # pragma: allowlist secret

high-security-encryptor-hse2-open \
  --input <ARCHIVE_PATH> \
  --output-dir <RESTORE_DIR> \
  --password-file <PASSPHRASE_FILE_PATH>  # pragma: allowlist secret
```

Password+keyfile wrappers are also supported by supplying both `--password-file` and `--keyfile` to create/open.

## Windows DPAPI Mode

On Windows, create a current-user DPAPI-backed archive:

```bash
high-security-encryptor-hse2-create \
  --root <ROOT_PATH> \
  --output <ARCHIVE_PATH> \
  --dpapi
```

Open it under the same Windows user context:

```bash
high-security-encryptor-hse2-open \
  --input <ARCHIVE_PATH> \
  --output-dir <RESTORE_DIR> \
  --dpapi
```

DPAPI mode is intentionally explicit. The conservative CLI workflow creates one wrapper at a time, so `--dpapi` is not combined with password or keyfile wrapper material by these commands.

## Inspect Container Metadata

Inspect safe container metadata without unlocking the archive or decrypting manifest/payload content:

```bash
high-security-encryptor-hse2-inspect \
  --input <ARCHIVE_PATH>
```

The inspect output includes non-secret metadata such as:

- HSE2 format version;
- preamble header length;
- creation timestamp;
- header auth algorithm and tag presence;
- access status marker;
- cipher suite names;
- manifest policy;
- payload chunk count;
- wrapper count and wrapper types.

It intentionally does not print ciphertext, nonces, auth tags, wrapped key blobs, raw key material, passwords, or keyfile bytes.

## Wrapper Metadata and Removal

List safe wrapper metadata without decrypting manifest or payload content:

```bash
high-security-encryptor-hse2-wrapper list \
  --input <ARCHIVE_PATH>
```

The list output includes wrapper ids, wrapper types, creation timestamps, labels, KDF profile names, and the `access_destroyed` header marker.

Add a new recovery wrapper after authenticating the existing container. The new wrapper gets its own id and may use a password, keyfile, password+keyfile, or Windows DPAPI:

```bash
high-security-encryptor-hse2-wrapper add \
  --input <EXISTING_ARCHIVE.hse2> \
  --output <ARCHIVE_WITH_RECOVERY.hse2> \
  --wrapper-id <NEW_WRAPPER_ID> \
  --new-password-file <NEW_PASSWORD_FILE> \
  --new-profile hardened \
  --password-file <EXISTING_UNLOCK_PASSWORD_FILE>
```

The add workflow writes a new output container and preserves the original. The existing unlock factors (`--password-file`, `--keyfile`, `--dpapi`) are distinct from new wrapper material. `--new-profile` applies to password-based wrappers; DPAPI wrappers do not use a password KDF profile.

Remove one selected wrapper after authenticating the current header with another valid unlock factor:

```bash
high-security-encryptor-hse2-wrapper remove \
  --input <ARCHIVE_PATH> \
  --output <UPDATED_ARCHIVE_PATH> \
  --wrapper-id <WRAPPER_ID> \
  --keyfile <KEYFILE_PATH>  # pragma: allowlist secret
```

The remove workflow writes a new output container. It does not mutate the input path unless `--output` points to the same file and `--overwrite` is used intentionally. The command refuses to remove the final wrapper; use `high-security-encryptor-hse2-access --help` for the separate explicit access-marker workflow.

## Wrapper Rewrap

Use `rewrap` to replace one existing wrapper with a new password, keyfile, password+keyfile combination, or Windows DPAPI wrapper in a single atomic header rewrite:

```bash
high-security-encryptor-hse2-wrapper rewrap \
  --input <INPUT_ARCHIVE> \
  --output <OUTPUT_ARCHIVE> \
  --wrapper-id <EXISTING_WRAPPER_ID> \
  --new-password-file <NEW_PASSWORD_FILE> \
  --keyfile <EXISTING_UNLOCK_KEYFILE>
```

`--new-wrapper-id` is optional and defaults to the replaced ID. Supply exactly one new wrapper type; `--new-keyfile` may be combined with `--new-password-file`, while `--new-dpapi` cannot be combined with either. Existing-container authentication uses `--password-file`, `--keyfile`, and/or `--dpapi`; those are separate from the `--new-*` wrapper material. The new output preserves the encrypted body byte for byte for both v2 and v3. The old wrapper is absent only in the successfully committed output; a failure leaves an existing target unchanged and removes the temporary output.

## Header Backup Export and Restore

Export a header backup from a complete `.hse2` container:

```bash
high-security-encryptor-hse2-header-backup export \
  --input <ARCHIVE_PATH> \
  --output <HEADER_BACKUP_PATH>
```

Restore a damaged-header container by replacing the current header frame with the backup header while preserving the encrypted body:

```bash
high-security-encryptor-hse2-header-backup restore \
  --input <DAMAGED_ARCHIVE_PATH> \
  --backup <HEADER_BACKUP_PATH> \
  --output <RESTORED_ARCHIVE_PATH>
```

Header backups include non-secret recovery metadata:

- body offset
- encrypted body SHA-256 digest
- body size
- container size

By default, restore verifies the encrypted body digest before writing the restored container. For advanced recovery cases, a manual body offset can be supplied:

```bash
high-security-encryptor-hse2-header-backup restore \
  --input <DAMAGED_ARCHIVE_PATH> \
  --backup <HEADER_BACKUP_PATH> \
  --output <RESTORED_ARCHIVE_PATH> \
  --body-offset 4096
```

`--no-verify-body-digest` exists for advanced recovery only and does not bypass metadata offset or size checks when metadata is present.

## Dry-run Planning

`hse2-create` can produce metadata-only archive planning output without writing a container:

```bash
high-security-encryptor-hse2-create \
  --root <ROOT_PATH> \
  --output <ARCHIVE_PATH> \
  --dry-run
```

## Boundaries

These CLI workflows intentionally do not add:

- hidden volumes;
- duress or decoy unlock behavior;
- automatic deletion of user keyfiles;
- in-place mutation of user archives.

Output-writing commands create a new container path by default. Use `--overwrite` only when replacing an output file is intentional.

## Verification

The Windows CI matrix exercises these workflows on Python 3.11, 3.12, and 3.13 through focused CLI tests and the full unittest suite.
