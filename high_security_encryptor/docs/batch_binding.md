# Batch Binding Draft

## Goal

Prevent manifest, password table, and template files from being silently reused across unrelated batches.

## Minimal binding fields

- `batch_id`: stable identifier for one encryption batch
- `file_count`: number of encrypted entries expected in the batch
- `manifest_fingerprint`: SHA-256 over canonical encrypted entry names

## Validation rule

Any imported password table or manifest-like payload must match all three fields.

## Current implementation status

- metadata generation implemented
- attachment/extraction helpers implemented
- validation helper implemented
- manifest/password-table/template serialization helpers implemented
- cross-batch validation tests implemented
- encrypted file integration is the next step
