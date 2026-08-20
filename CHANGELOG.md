# Changelog

All notable changes to Sentra will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and Sentra follows [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-08-20

### Added

* User signup and login
* JWT access-token authentication
* Refresh-token sessions
* Secure refresh-token hashing
* Refresh-token rotation
* Refresh-token reuse detection
* Refresh-token family revocation
* Session expiration
* Authentication hooks
* Custom user adapters
* Custom refresh-session adapters
* TypeScript type declarations
* ESM package build
* Comprehensive automated test suite
* GitHub Actions CI

### Security

* Raw refresh tokens are never persisted.
* Refresh tokens are hashed before storage.
* Reuse of revoked refresh tokens is detected.
* Refresh-token families can be revoked after token reuse detection.

[1.0.0]: https://github.com/akashbisht004/Sentra/releases/tag/v1.0.0
