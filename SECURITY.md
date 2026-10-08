# Security

Do not post credentials, database payloads, or exploitable vulnerability
information in public issues. Use GitHub's private vulnerability reporting
for this repository when enabled, or arrange a private channel with a
repository maintainer before sharing sensitive details.

Reports should include the affected SDK revision, Go version, operating
system, and a minimal reproduction using synthetic data. Never use the keys
under testdata/tls in a deployment; they are public test fixtures.

Maintainers should enable private vulnerability reporting before public
release. Only releases explicitly listed as supported by the project should
be assumed to receive security updates; this migration candidate is unreleased.
