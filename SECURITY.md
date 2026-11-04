Security Policy

Digital Data Depository (DDD) protects local files with encryption and authenticated vault structures. Reports about vulnerabilities, cryptographic weaknesses and unsafe data handling are taken seriously.

## Supported Versions

Security fixes are provided for the latest release on the `main` branch. Older builds do not receive security updates.

| Version | Supported |
| --- | --- |
| 1.0.x | Yes |
| < 1.0 | No |

## Reporting a Vulnerability

Do not open a public issue, discussion or pull request containing vulnerability details, exploit code or vault data.
New reports are acknowledged within 14 days.

**Preferred method:** use GitHub private vulnerability reporting, when it is enabled for this repository:

1. Open the repository's **Security** tab.
2. Select **Report a vulnerability**.
3. Submit the report privately.

**Alternative:** email [mrnoxxgithub@proton.me](mailto:mrnoxxgithub@proton.me).

Please include:

- the affected version or commit;
- operating system and build type;
- the component involved, such as the vault engine, interface or release binary;
- a clear description of the issue and its security impact;
- reproduction steps or a minimal proof of concept;
- relevant logs or screenshots with sensitive values removed.

Do not send real vault files or passwords. Reproduce the issue with a newly created test vault containing fictional data.

## In Scope

- Encryption, key derivation, key wrapping and nonce generation.
- Authentication tags, associated data and header verification.
- Vault index and header parsing.
- Memory locking and key or plaintext zeroization.
- Vault file locking, temporary files, compaction and password rekeying.
- Export path handling and overwrite protection.
- Tauri permissions, capabilities and content security policy.
- Release binary integrity and update behavior.

## Out of Scope

- A forgotten or lost password. DDD has no recovery mechanism.
- Data loss caused by deletion without a backup.
- Malware, keyloggers or an attacker with control of the operating system while the vault is unlocked.
- Restoration of a complete older copy of the vault file.
- Swap files, hibernation files, crash dumps or shell history created by the operating system.
- Metadata contained inside files stored by the user.
- Plaintext copies exported deliberately by the user.
- Social engineering or physical access attacks.

Reports about third-party dependencies are considered when the issue can affect DDD or its users.

## Testing Guidelines

- Test only vaults and files that you own or have explicit permission to use.
- Use copies of test data, never production or third-party vaults.
- Do not perform denial-of-service attacks, destructive tests against shared systems or social engineering.
- Keep exploit details private until a fix has been released and disclosure has been coordinated.

## Response and Disclosure

The maintainer will make a best effort to acknowledge the report promptly, assess its impact and prepare a fix. Please allow reasonable time for investigation and for a corrected release before publishing details.

Coordinated disclosure is expected. Credit can be included in the release notes when requested. No bug bounty is offered.
