### Changed

- `make lint` runs actionlint over `.github/workflows/` ([#66]), so workflow
  syntax, expressions and runner labels are checked before CI reads them. The
  new `actionlint` target fails when actionlint or shellcheck is absent:
  without shellcheck actionlint silently disables its `run:` script checks.
  CI's lint job installs actionlint and a pinned, checksum-verified shellcheck
  (`scripts/install-shellcheck.sh`) before `make lint`.
- `make trivy-fs`, and with it `make security`, now fails with an install
  hint when trivy is not on PATH instead of skipping with exit 0. With trivy
  present the scan is unchanged: `vuln,secret` scanners, CRITICAL/HIGH,
  exit code 1.

[#66]: https://github.com/jeremyhahn/go-auth/issues/66
