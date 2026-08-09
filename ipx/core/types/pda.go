package types

// PDAMarker is what a program derived address appends to its seeds before
// hashing, so that a PDA can never be produced by any other derivation.
//
// It is why CreateWithSeed refuses an owner ending in these bytes: a caller
// able to choose such an owner could make that derivation land on an address
// a program believes only it can authorize.
//
// It is exported because the derivation itself lives in core, next to the
// programs whose ids go into it, while the rule it enforces is checked here.
const PDAMarker = "ProgramDerivedAddress"
