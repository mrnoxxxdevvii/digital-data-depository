# Contributing to Digital Data Depository

Thank you for your interest in improving Digital Data Depository (DDD). The project is a local-first encrypted vault built with Tauri 2, a Rust backend and a plain HTML, CSS and JavaScript interface. Contributions of all kinds are welcome.

## How to Contribute

### Reporting Bugs

Open a public issue on GitHub and include:

- the DDD version or commit;
- the operating system and whether you use the release binary or a local build;
- clear steps to reproduce the problem;
- the expected and actual behavior;
- relevant error messages, with sensitive values removed.

Use a newly created test vault with fictional data. Do not attach real vault files, passwords, keys or personal documents. If the problem may have a security impact, do not open a public issue; follow [SECURITY.md](SECURITY.md) instead.

### Feature Requests

Open an issue and describe the problem you want to solve, not only the solution you have in mind. Explain how the feature fits a local, offline encrypted vault and whether it affects the on-disk format or the user interface. For larger changes, open an issue before writing code so the design can be agreed on first.

### Code Changes

Fork the repository, create a branch and submit a pull request against `main`. Make sure the project builds and all tests pass before submitting. Keep each pull request focused on one logical change and avoid unrelated refactoring or reformatting.

## Development Setup

Prerequisites:

- Rust 1.90 or newer;
- Microsoft C++ Build Tools with the Desktop development with C++ workload;
- WebView2 runtime, included with Windows 10 and 11 by default.

Build and run from source:

```sh
cd src-tauri
cargo run --release
```

The binary is written to `src-tauri/target/release/ddd.exe`.

Run the test suite:

```sh
cd src-tauri
cargo test
```

The interface in `ui/` is plain HTML, CSS and JavaScript embedded into the binary at compile time. DDD does not use npm and has no frontend build step; do not introduce a framework or a bundler.

## Tests

Add regression tests for every bug fix and tests for new backend behavior. Changes to vault creation, encryption, indexing, compaction or rekeying should include round-trip, wrong-password and tamper-detection coverage where applicable. Interface changes should be tested manually in the running application; mention the operating system and the steps you performed in the pull request.

Do not use real vaults or production data in tests, screenshots or issue attachments.

## Security-Sensitive Changes

DDD stores user files in an authenticated encrypted container. The following properties are part of the design and must not be weakened:

- Argon2id parameters and the password-to-key derivation;
- random key generation and AES-256-GCM key wrapping;
- unique nonces for every encryption operation;
- associated data binding for objects, the index and the header;
- HMAC verification of the vault header before the index is read;
- exclusive file locking while a vault is open;
- memory locking and zeroization of keys and plaintext buffers;
- the export guard that prevents overwriting the vault or writing outside the chosen destination;
- the restricted Tauri capabilities and content security policy.

Changes that alter the on-disk format require an explicit version bump, a migration path and tests that open vaults created by the previous version. Do not silently change field layouts, nonce sizes, associated data or KDF parameters.

## What Not to Submit

- real vault files, passwords, keys or personal documents;
- files matching `*.ddd`, `src-tauri/target/`, `src-tauri/gen/` or other build output;
- logs, crash dumps, temporary files or editor configuration;
- compiled binaries or installers in a normal source pull request;
- unrelated changes mixed into a bug fix or feature pull request.

## Pull Requests

- Target the `main` branch.
- Describe what changed, why it is needed and how it was tested.
- Link the related issue when one exists.
- Keep the branch up to date with `main` and resolve conflicts before review.
- Be prepared to revise the change based on review comments.

Review is best effort. There is no guaranteed response time and no bug bounty.

## License

DDD is released under the MIT License. See [LICENSE](LICENSE). By submitting a contribution you agree that it may be distributed under the same license.
