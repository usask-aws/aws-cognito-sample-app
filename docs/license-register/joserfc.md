# joserfc (with cryptography)

## License Register Entry

**Artifact:** joserfc `>=1.7` (1.7.7 current at the time of writing), plus its runtime dependency
cryptography (50.0.2 current) and that package's dependencies cffi and pycparser
**Type:** library (Python runtime dependency of the Flask app)
**Source:** https://pypi.org/project/joserfc/ — https://github.com/authlib/joserfc (maintained by
Hsiaoming Yang, the author of Authlib); https://github.com/pyca/cryptography
**License (SPDX):**
- joserfc: BSD-3-Clause
- cryptography: Apache-2.0 OR BSD-3-Clause
- cffi: MIT-0
- pycparser: BSD-3-Clause

**Classification:** permissive (all four)
**Commercial/institutional use permitted:** yes
**Obligations:** retain the copyright and license notices. The app ships as a container image
built from PyPI wheels, which carry each package's license file in its `.dist-info`; nothing is
redistributed outside that image.
**Transitive licenses introduced:** none non-permissive. joserfc's optional `drafts` extra
(pycryptodome) is not installed.
**Decision:** approved
**Determined by:** project owner
**Date:** 2026-10-21
**Notes:** used only to verify RS256 signatures on Cognito ID and access tokens against each
user pool's JWKS ([app/oidc.py](../../app/oidc.py)).

## Dependency Audit: joserfc >=1.7

**Date:** 2026-10-21
**Added by:** project owner (AI-assisted audit)
**Purpose:** verify the signatures and decode the claims of Cognito-issued JWTs (RS256, JWKS).

**CVE check (OSV, 2026-10-21):**
- joserfc: four advisories, all fixed at or below 1.6.8 (CVE-2025-65015, CVE-2026-27932,
  CVE-2026-48990, CVE-2026-49852). The `>=1.7` floor excludes every affected version.
- cryptography: every advisory is fixed at or below 50.0.0 (the latest, CVE-2026-69247 PKCS#7
  decryption, in 50.0.0). joserfc's own floor is `cryptography>=45.0.1`, which would allow
  versions affected by advisories fixed in 46.0.5–50.0.0. A fresh install resolves 50.0.2, and the
  advisories concern PKCS#7, X.509 path building, name constraints, SECT curves and non-contiguous
  buffers, none of which RS256 verification uses. Even so, `requirements.txt` pins an explicit
  `cryptography>=50.0` floor so no affected version can be installed (owner decision, 2026-10-21).

**Maintenance:** active. 1.7.7 released 2026-10-19; cryptography 50.0.2 released 2026-09-30.
**License:** see the register entry above.
**Necessity:** the standard library has no RSA signature verification. joserfc is a focused
JOSE/JWT library (no HTTP client, no framework). The token request and PKCE use the standard
library, so no HTTP client dependency is added. Alternatives considered in the design: Authlib
(larger, includes OAuth clients we don't need), PyJWT (would also need cryptography).
**Transitive deps added:** 3 — cryptography, cffi, pycparser.

**Decision:** approved (project owner, 2026-10-21)
**Notes:** keep the `>=1.7` and `cryptography>=50.0` floors; re-check OSV when the image is rebuilt.
