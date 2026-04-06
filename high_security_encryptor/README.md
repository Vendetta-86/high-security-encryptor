# High Security Encryptor

Standalone project for a hardened local encryption tool focused on high-value data and hostile-environment safeguards.

Phase 1 scope:
- streaming file format design
- integration test harness
- initial package layout

Project layout:
- `docs/streaming_format.md`: file format and compatibility draft
- `src/high_security_encryptor/`: implementation package
- `tests/`: integration and unit tests

Current status:
- new project scaffolded separately from the original tool
- streaming file encryption implemented
- legacy `GCM1` compatibility decryption implemented
- batch binding and encrypted sidecar artifacts implemented
- non-UI batch workflow implemented for plain files and folders
- folder packages support selected inner files being independently encrypted
- inner encrypted folder members can carry bound encrypted sidecars inside the package
- end-to-end behavior encoded as executable tests
