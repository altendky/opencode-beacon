# Release

Release tags have the form `vX.Y.Z` and must exactly match the Cargo package
version.
Tag CI publishes the crate through crates.io Trusted Publishing, builds static
musl binaries for Linux x86-64 and ARM64, creates archives containing the binary
and both licenses, and uploads the archives plus `SHA256SUMS` to a GitHub
Release.
Release retries first preserve an existing release or create it only after a
confirmed API 404, then upload all assets separately with `--clobber`.
Authentication and other API failures remain fatal.
The publish gate includes tests run from the extracted Cargo package, so the
published crate contains the fixtures needed to compile and execute its tests.

Before the first release, configure crates.io Trusted Publishing for
`altendky/opencode-beacon` and workflow `ci.yml`.
The GitHub repository and release permissions must also exist.
No long-lived crates.io token is required.
