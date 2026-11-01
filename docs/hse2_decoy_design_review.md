# HSE2 Decoy / Duress Design Review

## Status

**Historical decision: no-go for claiming plausible deniability in HSE2 v2/v3.** This pre-implementation review correctly rejected adding a visible duress wrapper or decoy payload to those formats. It does not block the separately versioned v4 alternate-view feature, which is now implemented and released. The current feature is explicitly disclosed as two views and makes no deniability claim.

The current v4 format supports an explicitly disclosed alternate-view workflow. It does not claim that an alternate unlock hides the existence of other content. The v2/v3 format and threat-model limitations recorded below remain applicable to those formats. Third-party review is not a project gate for this self-use project.

## Security goal under review

The original Phase 8 language combines two different goals:

1. **Alternate-content unlock:** credentials can select different plaintext views.
2. **Plausible deniability:** an observer who can inspect the archive and relevant system artifacts cannot distinguish a decoy-only archive from one containing additional protected content, within a stated attacker model.

Goal 1 does not establish goal 2. Any implementation must name its goal precisely. HSE2 must not use terms such as “hidden volume,” “undetectable,” or “plausible deniability” for a feature that only implements alternate-content unlock.

## Attacker model to resolve before implementation

The current plan does not specify which of these capabilities the feature is meant to resist:

- one-time possession of a copied container;
- repeated copies of the same container before and after updates;
- access to the host OS, process memory, filesystem metadata, logs, temp files, and backups;
- ability to compare header backups, wrapper-management output, release versions, and command history;
- coercion to provide one credential, multiple credentials, or an explanation of how the tool works;
- ability to execute the application and observe timing, error behavior, memory use, and output files.

Without a bounded model, “not distinguishable” is not a testable security requirement. A container-only guarantee must not be presented as protection against host artifacts or repeated-snapshot analysis.

## Current format observations

These are visible without decrypting the manifest or payload:

| Observable | Current source | Consequence for a naive decoy extension |
|---|---|---|
| Wrapper types and KDF metadata | Authenticated JSON header; `WrapperRecord.type` is restricted to known types | A `duress` wrapper label would disclose the feature directly. |
| Format version, chunk count, chunk size, padding mode | Authenticated header and fixed preamble | Additional records or a second payload region can change authenticated layout fields. |
| Manifest and payload record framing | v3 `MNF3` followed by declared `CHK3` records | A second manifest/record family is structurally observable unless the entire framing design changes. |
| Container size and update deltas | File length and encrypted record lengths | Equal-size decoy and real views are not enough to address repeated snapshots or host artifacts. |
| Header backup offsets, body size, and digest | `.hse2.header` recovery metadata | Backup files can expose structural changes and correlate container versions. |
| CLI/GUI result summaries and logs | Existing command and GUI workflow | Any credential-dependent labels, errors, paths, timing, or output differences may become evidence. |

Relevant implementation points include `hse2/models.py` (`WrapperRecord.VALID_TYPES`), `hse2/container_codec.py`, `hse2/container_stream.py`, `hse2/streaming_file_io.py`, `hse2/inspect.py`, header backup code, and GUI result summaries. This is a source-level inventory, not a cryptographic proof.

## Candidate directions considered

### A. Add a visible duress wrapper and a second manifest/payload

**Reject.** The header or body framing would reveal additional decoy machinery. This is an alternate-content feature, not a deniable one.

### B. Put decoy and real views behind the same visible wrapper and fixed-size record stream

**Not specified; do not implement from this description.** This would require a new format and key schedule, a precise definition of how each credential selects an authenticated view, how unused bytes are indistinguishable from valid encrypted records, how size and update behavior are controlled, and how parsing remains fail-closed. A successful unit test or one-time byte comparison cannot establish indistinguishability under an unspecified attacker model.

### C. Reuse v2/v3 with an application-level alternate restore directory

**Reject as a duress claim.** This can be an ordinary alternate-content workflow if clearly disclosed, but the archive metadata, host state, or application behavior may reveal that multiple views exist.

## Original review gates (historical; apply only if true deniability is reconsidered)

1. Approve a bounded attacker model and explicitly list excluded host/system risks.
2. Write a versioned wire-format proposal covering header, key derivation, record allocation, padding, updates, backups, compatibility, and all parser failure modes.
3. Define externally observable behavior for both credentials, including inspect output, errors, timings, logs, GUI summaries, and restore paths.
4. Prove by construction which archive-only observations are intended to be indistinguishable; identify the observations the format cannot hide.
5. Complete a documented local cryptographic/design review before implementation and a separate code review plus regression suite before release. Record that this is self-review, not external certification.
6. Keep all destructive behavior out of ordinary open. A credential must never silently delete real content, wrappers, or evidence.
7. Test legacy readers, malformed and truncated records, wrong credentials, tampering, repeated snapshots, equal-size view constraints, backup/restore, and GUI/CLI side channels. These tests can falsify claims but cannot prove real-world deniability by themselves.
8. Use an explicit limited-feature name and warning if the eventual implementation only offers alternate-content unlock. Do not imply legal, forensic, or coercion safety.

## Original decision (historical)

At review time, Phase 8 design work had resumed at the proposal stage. The v2/v3 no-go remains in force: the implementation does not patch `WrapperRecord` or existing wire formats, and no credential automatically deletes real data or wrapper material. The proposal has since been implemented as isolated v4 alternate-view functionality; it is not a deniability construction.

## 2026-11-01 Current Status

The user authorized local implementation for self-use without third-party or independent-review gates and selected the scope “alternate-content feature, no plausible-deniability claim.” V4 has isolated wire codecs, fixed-layout file create/read/update workflows, Python CLI commands, and experimental GUI create/open/replace actions. Local tests and packaged Windows Release ZIP acceptance passed; v0.7.0 is published. Further fuzz/property exploration may improve confidence, but it is not an unfinished roadmap gate. The v2/v3 formats remain unchanged, and this project makes no deniability claim.

## References

- [VeraCrypt Security Requirements and Precautions Pertaining to Hidden Volumes](https://veracrypt.io/en/Security%20Requirements%20for%20Hidden%20Volumes.html)
- [VeraCrypt Hidden Volume](https://veracrypt.io/en/Hidden%20Volume.html)
- [HSE2 container format](hse2_format.md)
- [HSE2 threat model](hse2_threat_model.md)
