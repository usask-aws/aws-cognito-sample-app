# segno

## License Register Entry

**Artifact:** segno `>=1.6` (1.6.6 current at the time of writing)
**Type:** library (Python runtime dependency of the Flask app)
**Source:** https://pypi.org/project/segno/ — https://github.com/heuer/segno (Lars Heuer)
**License (SPDX):** BSD-3-Clause (GitHub license detection; PyPI classifier "BSD License")
**Classification:** permissive
**Commercial/institutional use permitted:** yes
**Obligations:** retain the copyright and license notice. The app ships as a container image built
from the PyPI wheel, which carries the license file in its `.dist-info`; nothing is redistributed
outside that image.
**Transitive licenses introduced:** none. segno has no runtime dependencies on Python 3.10 or
later (`importlib-metadata` only below 3.10).
**Decision:** approved
**Determined by:** project owner
**Date:** 2026-10-21
**Notes:** draws the TOTP enrolment QR code on `/account` as inline SVG
([app/account_web.py](../../app/account_web.py)). The QR content is built by the app from the
Cognito-issued secret; no user input reaches the markup.

## Dependency Audit: segno >=1.6

**Date:** 2026-10-21
**Added by:** project owner (AI-assisted audit)
**Purpose:** render the `otpauth://` URI as a QR code so an admin can enrol an authenticator app.

**CVE check (OSV, 2026-10-21):** no known vulnerabilities.
**Maintenance:** maintained, low churn. Latest release 1.6.6 (2025-03-12); last push to the
repository 2026-07-23; not archived. A slow release cadence fits a finished, single-purpose
encoder that isn't security-relevant (it doesn't parse untrusted input here).
**License:** see the register entry above.
**Necessity:** the standard library has no QR encoder. The fallback (showing only the text
secret) works but makes enrolment harder. segno is pure Python with no dependencies and writes
SVG directly, so no imaging library is needed.
**Transitive deps added:** 0.

**Decision:** approved (project owner, 2026-10-21)
**Notes:** keep the `>=1.6` floor; re-check OSV when the image is rebuilt.
