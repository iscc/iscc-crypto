# Changelog

## [0.6.0] - Unreleased

- Added sign command for JSON document signing
- Added verify command for signed JSON files

## [0.5.0] - 2025-08-13

- Added controller-based verification method support in VC signing
- Updated dependencies in lock file

## [0.4.0] - 2025-07-28

- Added cryptographic nonce generation with embedded node identifier
- Added keygen command for cryptographic key generation
- Added version display in CLI help output
- Added -h as short notation for the help option in CLI
- Added "Getting Started" documentation
- Updated project URLs in pyproject.toml
- Updated version retrieval method

## [0.3.0] - 2025-06-10

- Added CLI for cryptographic identity management with setup, validate-identity, and info commands
- Added signature version tracking for ISCC signatures
- Added URI resolution module with support for did:key, did:web, HTTP(S), and CID documents
- Added validation for Controlled Identifier Documents
- Added ISCC signature specification and example
- Enhanced JSON verification with external public key support
- Migrated from Poetry to UV for dependency management
- Updated GitHub Actions workflow for UV setup

## [0.2.0] - 2024-12-09

- Added https://www.w3.org/TR/vc-di-eddsa/ context injection

## [0.1.0] - 2024-12-09

- Initial alpha release
