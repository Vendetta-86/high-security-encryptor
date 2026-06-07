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

## Wrapper List and Remove

List safe wrapper metadata without decrypting manifest or payload content:

```bash
high-security-encryptor-hse2-wrapper list \
  --input <ARCHIVE_PATH>
```

Remove one wrapper after authenticating the current header with another valid unlock factor:

```bash
high-security-encryptor-hse2-wrapper remove \
  --input <ARCHIVE_PATH> \
  --output <ARCHIVE_WITHOUT_WRAPPER_PATH> \
  --wrapper-id <WRAPPER_ID> \
  --keyfile <KEYFILE_PATH>  # pragma: allowlist secret
```

`wrapper remove` refuses to remove the last wrapper. Use `hse2-access destroy` only for explicit access destruction.

## Destroy Access

Write a copy of a container with all unlock wrappers removed:

```bash
high-security-encryptor-hse2-access destroy \
  --input <ARCHIVE_PATH> \
  --output <DESTROYED_ARCHIVE_PATH> \
  --confirm "I UNDERSTAND THIS WILL MAKE THE DATA PERMANENTLY UNRECOVERABLE"
```

This does not delete or overwrite the encrypted payload. It removes the wrapper metadata needed to recover DEK/MEK and writes an `access_destroyed` marker in the header. Without an external header backup or another valid copy of the original header, the destroyed output is intentionally unrecoverable.

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
