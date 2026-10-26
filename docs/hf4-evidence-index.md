# HF4 archive evidence index

This index records archives that have passed `hf4-archive-verify` and a human
review. It is not a supply statement and does not imply activation.

No archives have been accepted yet.

| Archive ID | Source ID | Operator ID | Signing key SHA-256 | Through height | Blocks SHA-256 | Bodies SHA-256 | Paired with | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| _(none)_ | | | | | | | | |

## Entry rules

- Add a row only after `verify-one` and a passing `verify-pair` against a
  distinct source, operator, and signing key.
- Record the `signing_key_sha256` from the verifier summary, never the raw key
  or any private material.
- Record the full `blocks_sha256` and `bodies_sha256`; short forms are not
  sufficient for an evidence index.
- Do not record private endpoints, personal data, or collection credentials.
- Keep the `Archive ID` unique. Do not overwrite a prior entry; mark it
  superseded and link the replacement.
- A row marked `accepted` means integrity and pairwise agreement passed. It does
  not mean the archive is the canonical chain or that a supply total is
  approved.
