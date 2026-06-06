# HSE2 Threat Model

This document describes the expected protection boundary for the experimental HSE2 workflows. It is operational guidance for users and maintainers; it is not a cryptographic proof.

## Assets

HSE2 workflows protect these assets:

- plaintext file contents before encryption and after successful restore;
- content-encryption keys wrapped by password, keyfile, password+keyfile, or Windows DPAPI wrappers;
- encrypted manifests and encrypted payload chunks inside `.hse2` containers;
- keyfiles generated or selected by the user;
- header backups used for recovery.

The most sensitive user-managed material is the wrapper material needed to open a container. In a keyfile workflow, losing the keyfile can make the container unrecoverable. Exposing the keyfile to another party can allow that party to open the container if they also have the `.hse2` file.

## In Scope

HSE2 aims to defend against:

- accidental disclosure of plaintext through normal CLI summaries or GUI status text;
- damaged container headers when a valid header backup and matching encrypted body are available;
- accidental use of the wrong keyfile or wrong password through authenticated unwrap and payload checks;
- local online guessing through existing CLI failure handling and explicit unlock material requirements;
- mistaken quickstart use by generating a minimal workspace with local files and copyable commands.

## Out of Scope

HSE2 does not currently defend against:

- malware or a compromised operating system reading plaintext, keyfiles, process memory, clipboard contents, or DPAPI material;
- an attacker who can modify the program itself before it runs;
- offline guessing of weak passwords against copied containers;
- loss of every valid wrapper factor and every valid backup;
- hidden volumes, plausible deniability, decoy unlock flows, or duress workflows;
- secure deletion guarantees on SSDs, network shares, cloud-synced folders, or journaling filesystems.

## Keyfile Workflows

A keyfile-backed archive depends on both the `.hse2` container and the keyfile. Recommended handling:

- store the keyfile separately from routine plaintext working directories;
- keep at least one offline backup of the keyfile when the data must remain recoverable;
- do not paste keyfile bytes into chat, issue trackers, logs, shell history, or screenshots;
- rotate by creating a new container with a new keyfile when exposure is suspected;
- treat file-sharing of the keyfile as equivalent to granting access to matching containers.

The quickstart wizard creates a random local keyfile for demonstration and first-run usability. Users should move from quickstart paths to an intentional storage plan before protecting important files.

## Password Workflows

Password-backed wrappers depend on password strength and KDF parameters. Use long, unique passphrases. Short or reused passwords remain susceptible to offline guessing if an attacker obtains the container.

Password files are accepted by CLI entry points to avoid interactive prompting in automation. Store those files with OS permissions appropriate for the local machine. Do not commit them to repositories or place them inside release assets.

## Windows DPAPI Workflows

Windows DPAPI wrappers bind unwrap capability to the selected Windows protection scope. Current-user DPAPI is useful for local convenience but is not a portability feature.

Expected boundary:

- the DPAPI-protected material usually opens only under the same Windows user context and system protection conditions;
- Windows account compromise can compromise DPAPI-protected HSE2 material;
- OS reinstall, profile loss, domain policy changes, or machine migration can make DPAPI-protected material inaccessible;
- DPAPI does not protect plaintext after a successful open operation.

For data that must survive account or device loss, keep a separate recovery factor such as an offline keyfile backup or another wrapper strategy when supported by the workflow.

## Header Backups

A `.hse2.header` backup contains the HSE2 header frame and non-secret recovery metadata. It does not contain plaintext payload chunks or decrypted keys. It can still reveal operational metadata, such as wrapper types, archive structure fields, and recovery offsets.

Recommended handling:

- store header backups with the same integrity expectations as the matching container;
- keep header backups separate from casual working directories;
- do not assume a header backup alone can recover data without the matching encrypted body and wrapper material;
- regenerate a header backup after changing container header structure or wrapper material.

## Body-Offset Recovery Metadata

Header backups may include metadata such as body offset, encrypted body size, encrypted body digest, and container size. This metadata is intended to recover when the current preamble or header is damaged but the encrypted body remains intact.

Risk boundary:

- the metadata is not plaintext data;
- the encrypted body digest can help verify body identity but may also reveal whether two backup/body pairs match;
- body size and offset reveal container layout information;
- restore should reject mismatched body size or digest unless the user explicitly enters an advanced recovery path.

## Quickstart Wizard

The HSE2 quickstart wizard is for first-run learning and local validation. It creates sample files, JSON configs, a local keyfile, and command notes. It now also offers one-click and single-step execution through the existing CLI boundary.

Boundary:

- it does not upload files or contact remote services;
- it does not hide generated files from the user;
- it does not automatically protect the generated keyfile beyond normal filesystem permissions;
- it does not turn the sample workspace into a production backup plan;
- it stops on the first non-zero command result and leaves diagnosis to the GUI log.

Before using HSE2 for valuable data, replace the sample workspace with deliberate storage, backup, and recovery decisions.

## GUI Boundary

The GUI is a command builder and local runner. It should not be treated as a separate cryptographic implementation. Encryption, validation, decryption, and recovery actions should continue to pass through the same CLI and library workflows used by tests.

GUI logs can contain paths, filenames, status text, and command output. Avoid screen-sharing or uploading logs when paths disclose sensitive project names or operational structure.

## Release and Packaging Boundary

Release artifacts must not include user configs, keyfiles, DPAPI blobs, generated quickstart workspaces, local caches, or plaintext test data beyond intentional repository fixtures.

Before tagging a release, run the release checklist and verify:

- committed-secret scanning passes;
- dependency audit passes;
- HSE2 CLI help and round-trip checks pass;
- Windows EXE bundles include intended entry points only;
- no user-generated quickstart workspace is included in the release asset.

## Incident Response

If wrapper material may be exposed:

1. Stop using the affected container for new data.
2. Create a new container with fresh wrapper material.
3. Move plaintext into the new container only on a trusted machine.
4. Retire old backups that contain the exposed wrapper material.
5. Keep the old container only if required for audit or recovery.

If a header backup is lost but the container still opens, export a new header backup. If both the header and backup are damaged, recovery is not expected unless a valid header copy exists elsewhere.

## Maintainer Checklist

When adding new HSE2 features, document whether they change:

- required wrapper factors;
- generated files or release artifacts;
- GUI logging behavior;
- recovery metadata;
- portability across machines and Windows users;
- failure handling and partial-output behavior.
