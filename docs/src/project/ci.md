# CI

CI runs formatting, Clippy, tests, documentation, dependency policy, package
validation, and Linux release builds.
Package validation extracts the generated crate and runs its complete unit and
documentation test suites, including published fixtures, from packaged source.
External GitHub actions are pinned to full commit hashes.
The aggregate required status is named `all`.

Pull requests and branch pushes validate release archives without publishing.
Tags additionally enable crates.io and GitHub Release publication after all
checks pass.
