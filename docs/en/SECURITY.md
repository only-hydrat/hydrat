<p align="center">
  <a href="../../SECURITY.md">Русский</a> · <strong>English</strong> · <a href="../zh-CN/SECURITY.md">简体中文</a>
</p>

# Security Policy

The Hydrat team treats gateway security, user privacy, and traffic isolation as primary concerns.

---

## Supported versions

| Version | Supported |
| :--- | :--- |
| `main` (current) | :white_check_mark: |

Critical security fixes are released promptly on `main`.

---

## Reporting a vulnerability

If you discover a security vulnerability in Hydrat:

1. **Do not open a public issue** describing the vulnerability or exploit.
2. Submit a report through [GitHub Security Advisory](https://github.com/only-hydrat/hydrat/security/advisories/new) or email the maintainer at only_hydrat@proton.me.
3. Include:
   - A description of the issue and its potential impact.
   - Reproduction steps or a proof of concept.
   - Affected components and configuration.
4. We will respond within 48 hours and coordinate the fix timeline before public disclosure.

---

## Hydrat security architecture

Hydrat is designed around defense in depth:

- **Restricted secret permissions:** configuration files containing private keys, including `wg0.conf` and `.env`, are created and read with mode `0600`.
- **Read-only containers:** the controller runs with a read-only root filesystem (`read_only: true`) and an isolated `tmpfs` for temporary files.
- **No default passwords:** the administration password is never embedded in images or configuration. The controller requires an explicitly configured strong `HYDRAT_ADMIN_PASSWORD` and fails to start when it is absent.
- **Russian egress leak protection:** `disallow_ru_egress` excludes egress nodes located in Russia from qualification to reduce deanonymization and blocking risks for sensitive traffic.
- **Gateway capabilities:** the gateway retains Docker's default capabilities and explicitly adds `NET_ADMIN` and `NET_RAW`; it does not run in `privileged` mode. This is not a least-privilege profile because WireGuard, routes, nftables, ports, and bind-mounted storage preparation require these permissions.
