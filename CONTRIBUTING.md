# Contributing

Keep changes focused and include tests that demonstrate the behavior being
changed. Run the checks in [docs/validation.md](docs/validation.md) before
submitting a pull request. Use synthetic endpoints, certificates and tokens.
Do not include deployment credentials, private addresses, or tunnel payloads
in issues, logs, examples or test fixtures.

Preserve TLS verification, bounded resources, stream isolation, half-close,
and the no-automatic-replay guarantee. Document public API or compatibility
changes in CHANGELOG.md. Keep transport tests independent of live services.
Changes use the repository's Apache-2.0 license; retain required attribution
when contributing assets from another source.
