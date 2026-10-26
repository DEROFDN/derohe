package dvm

import _ "embed"

// SeamlessMigrationContract is installed at the reserved migration SCID at HF4.
// It is a stateless marker; value moves only through the base layer's existing
// confidential transfer proof, never through public DVM BurnValue semantics.
//
//go:embed hardcoded_sc/seamless_migration.bas
var SeamlessMigrationContract string
