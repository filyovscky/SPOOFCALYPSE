# Third-party material

## Adapted code and data

The `TABLE` decision matrix in `spoof_check.py` is adapted from
[Spoofy](https://github.com/MattKeeley/Spoofy), created by **Matt Keeley**.
Its license is **CC BY-NC 4.0**.

The license permits sharing and adaptation for non-commercial purposes,
with attribution, a license link and an indication of changes.
SPOOFCALYPSE retains this restriction. Commercial reuse of the upstream
material requires separate permission from its rights holder.

Changes: SPF/DMARC validation through checkdmarc, corrected subdomain handling,
DNS error handling, risk factors, DKIM key parsing and .eml verification,
new scope handling, command-line interface and report formats.
Upstream delivery tests have not been repeated.

- Original project: https://github.com/MattKeeley/Spoofy
- Upstream license copy: [licenses/spoofy/LICENSE](licenses/spoofy/LICENSE)
- Complete CC BY-NC 4.0 text: [LICENSE](LICENSE)
- Attribution: [NOTICE](NOTICE)

## Library dependencies

These packages are installed as dependencies. Their source code is not copied
into SPOOFCALYPSE's Python modules. Their own licenses remain in effect.

| Package | Version | License | Use |
| --- | --- | --- | --- |
| [checkdmarc](https://github.com/domainaware/checkdmarc) | 6.0.4 | Apache-2.0 | SPF/DMARC validation |
| [cryptography](https://github.com/pyca/cryptography) | 50.0.2 | Apache-2.0 OR BSD-3-Clause | RSA/Ed25519 public keys |
| [dkimpy](https://launchpad.net/dkimpy) | 1.1.8 | Zlib-style license in the distributed LICENSE | DKIM signature verification |
| [pyspf](https://github.com/sdgathman/pyspf) | 2.0.14 | Python Software Foundation License | Development-only comparison tests |

The upstream dkimpy package describes its license as BSD-like. The exact
distributed terms are preserved in [licenses/dkimpy/LICENSE](licenses/dkimpy/LICENSE).
License copies for checkdmarc and cryptography are also in `licenses/`.

Existing dependencies: dnspython (ISC), requests (Apache-2.0), rich (MIT).
Transitive dependencies retain their respective licenses.
Exact installed versions are listed in `requirements.lock.txt`.
