# HSE2 CLI Workflows

HSE2 remains an explicit experimental workflow, but the core archive lifecycle is now available through focused CLI entry points. Commands that need passwords either prompt without echo or read them from redirected standard input; summaries do not print plaintext key material.

The path values below are placeholders. Replace angle-bracketed values with local test files when running the commands.

## Create and Open

For an HSE2 v5 two-view container, `v5-verify` authenticates the selected view's descriptor and every active payload record without writing restored files. `v5-preview` authenticates the selected view metadata and reports its file/byte/chunk totals, whether the proposed restore directory already exists, and the destination volume's currently available space. Preview does not authenticate every payload record; use verify when you also want a complete payload integrity check. Space can change after preview, so restore checks it again before staging output.

```bash
high-security-encryptor hse2 v5-verify \
  --input <V5_ARCHIVE_PATH>

high-security-encryptor hse2 v5-preview \
  --input <V5_ARCHIVE_PATH> \
  --output-dir <NEW_RESTORE_DIRECTORY>
```

Both commands prompt for the selected view password without echoing it. For automation, add `--password-stdin` and pipe the password through standard input; never put it directly in command arguments. `v5-verify` holds only one authenticated chunk at a time and reports that plaintext was not written. A successful result proves record authentication and length consistency for the selected live view; v5 does not store a plaintext digest, so this is not a comparison against an archive-stored plaintext hash. `v5-preview` requires a new destination directory. `v5-open` performs its own target and free-space preflight before it creates staging output.

These commands are experimental and do not claim hidden-volume behavior, deniability, or protection against local metadata observation.

## Change One v5 View Password

Change the password for the view unlocked by the current password:

```bash
high-security-encryptor hse2 v5-password-update \
  --input <CURRENT_V5_ARCHIVE> \
  --output <UPDATED_V5_ARCHIVE>
```

The CLI asks for the current password, then asks for and confirms the new password. The operation writes a complete new archive copy. In that output, only the selected credential slot changes; the other slot, encrypted descriptors, records, and footer are copied unchanged. The source archive remains usable with the old password. The destination must be a different path and needs enough free space for another full-size container. `--force` replaces an existing destination file after the new copy has been built.

Choose a new password that differs from the other view's password. Because this operation only asks for the selected view's current password, it cannot check whether the new password matches the other view. The existing source and any older copies keep their old credentials, so store the updated archive safely and verify it with the new password before deciding how to retain older copies. Do not assume old copies or backups have changed when updating this output.

Automation may add `--passwords-stdin`; provide exactly three non-empty lines: current password, new password, and new password confirmation. Do not place passwords in command arguments or shell history.

The workflow rejects an incorrect current password, an unchanged password, an input path used as the output, and a known insufficient-space condition. A failed copy or final replacement leaves the source archive untouched and removes the incomplete temporary output. v5 remains experimental and this operation does not add deniability or erase older copies.

Inspect an HSE2 keyfile before using it:

```bash
high-security-encryptor hse2 keyfile inspect --input <KEYFILE_PATH>
```

The JSON result includes the byte length, the 32-byte minimum, HSE2 suitability, and a SHA-256 fingerprint. The command streams the file in bounded blocks and never prints keyfile contents. The fingerprint can identify the same keyfile across records, so treat it as metadata.

Create, open, and wrapper-management commands warn on stderr if a keyfile and an input/output `.hse2` archive share a directory. Keep the keyfile in a separate secure location so copying the archive directory does not copy both factors.

`high-security-encryptor-hse2-create --validate-after-create` reopens the completed v2/v3 archive, authenticates the header and encrypted manifest, and verifies every payload authentication tag without writing plaintext. It returns a nonzero status if validation fails; the already-created archive remains on disk. The GUI create action enables this check by default.

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

Add `--validate-before-open` to authenticate the complete archive before restoring files. If authentication fails, the CLI returns an error before creating the output directory. This reads the archive twice and is optional; the normal open path still authenticates each chunk as it restores it.

Set `HSE2_RESTORE_TEMP_DIR` to an existing directory to control where per-file plaintext temporary files are staged during restore. The directory must be on the same filesystem volume as the restore destination so the final atomic replacement remains supported. If unset, temporary files remain beside each destination file. Invalid or cross-volume configuration fails before the restore destination is created.

Validate an existing v2/v3 archive without restoring it:

```bash
high-security-encryptor hse2 validate-archive \
  --input <ARCHIVE_PATH> \
  --keyfile <KEYFILE_PATH>  # pragma: allowlist secret
```

The equivalent focused entry point is `high-security-encryptor-hse2-archive-validate`. It authenticates the header, encrypted manifest, and every payload tag, and reports that no plaintext was written.

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

To reduce exact per-file size leakage, opt in to padding each non-empty file's final encrypted chunk to the configured chunk size:

```bash
high-security-encryptor-hse2-create \
  --root <ROOT_PATH> \
  --output <ARCHIVE_PATH> \
  --keyfile <KEYFILE_PATH> \
  --pad-last-chunk
```

Padding adds up to one chunk of storage per non-empty file. The encrypted manifest preserves original sizes, so open restores exact files. Container size and total chunk count remain visible. The authenticated padding mode requires a reader that supports this option; older readers fail closed.

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

HSE2 DPAPI wrappers use the current Windows user scope. Account or device changes, Windows reinstall, or moving the archive may make this wrapper unusable. Create a separate password or keyfile wrapper for recovery; successful create/add/rewrap commands print this warning. Do not treat a header backup as a replacement for that recovery factor.

The standalone `dpapi-protect` command also supports `--scope local_machine` for protected keyfile blobs. Windows documents that any user on the protecting computer can decrypt a blob created with this scope, so use it only when shared local-machine access is intended. The GUI and CLI display this warning when the scope is selected. See [Microsoft's CryptProtectData documentation](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata).

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

After a successful `hse2-create`, the CLI recommends exporting a header backup and prints a ready-to-copy command to stderr. Its JSON result also includes `header_backup_recommended`, `header_backup_path`, and `header_backup_export_argv`; dry-run output does not recommend a backup because no container was written. A header backup only restores header metadata. It cannot replace or recover the password, keyfile, or DPAPI access conditions needed to unlock the container.

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

By default, restore uses a valid current header to locate the encrypted body, then verifies its size and SHA-256 against the backup metadata. This supports restoring an older wrapper header after wrapper changes that alter the header length. If the current header is damaged, restore falls back to the backup's recorded body offset; a manual offset can be supplied for advanced recovery cases:

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
