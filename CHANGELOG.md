# Changelog

All notable changes to this project will be documented in this file.

## [0.1.0] - 2026-04-05

### Added

- Initial implementation of the alnumid CredentialComposer plugin
- `ComposeWorkloadJWTSVID` adds a structured alphanumeric identifier as a custom claim to JWT-SVIDs
- SPIFFE ID is split into trust domain and path; each part is independently hashed with SHA256
- Configurable claim name (`claim_name`), trust domain hash length (`domain_chars`), and path hash length (`path_chars`) via `plugin_data`
- Cross-domain collision resistance: workloads from different trust domains always produce different identifier prefixes
- Input validation for `claim_name`, `domain_chars`, and `path_chars`
- Unit tests covering output length, hex character set, determinism, cross-domain prefix uniqueness, and same-domain path uniqueness
