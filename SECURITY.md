# Security policy

## Reporting a vulnerability

Please do not report security problems in public issues, pull requests or discussions.

Report them privately through GitHub's private vulnerability reporting: open this repository's **Security** tab and choose **Report a vulnerability**. Include the affected version, a description of the problem and, if you can, the steps to reproduce it.

A vulnerability in the broker itself, or in the ion protocol, may affect every client. Report it the same way. We coordinate the fix across `interceptor-server` and all six `interceptor-client-*` repositories.

## Coordinated disclosure

- We work with you on a fix and a release date, and ask you to keep the report private for up to **90 days** from the report, or until a fixed release is out, whichever comes first.
- We cut a patch release for every CVE that affects a shipped version, and credit you in the advisory unless you prefer otherwise.

## Supported versions

| Version | Supported |
|---|---|
| Latest release of the current major | ✓ |
| Unreleased (`main`) | ✓ |
| Older releases | Upgrade to the latest release |
