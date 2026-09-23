# Versioning, Compatibility, and Deprecation Policy

## Versioning

Specifications and reference crates are versioned together with semantic
version tags (`vX.Y.Z`) on this repository. Major version zero (`0.Y.Z`)
signals an evolving surface: any release may change types, wire formats, or
semantics.

## Compatibility

- Within `0.Y.Z`, patch releases fix errors without changing semantics.
- Minor releases may extend the surface (new types, new optional fields)
  without breaking existing consumers.
- Breaking changes require a minor version bump while major is zero, and a
  major bump once `1.0.0` exists. Every breaking change ships migration
  notes in CHANGELOG.md.
- Consumers record the protocol version they target (see CONSUMERS.md) and
  upgrade by explicit decision, never silently.

## Deprecation

- A deprecated item is marked in specs and reference code, with its
  replacement named, for at least one minor release before removal.
- Removals are listed in CHANGELOG.md with the version that removes them
  and the migration path.
- Security fixes are exempt from the waiting period and are disclosed
  immediately in CHANGELOG.md.
