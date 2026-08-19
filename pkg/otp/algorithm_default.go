//go:build !fips140only

package otp

// defaultAlgorithm is the digest used when Config.Algorithm is empty.
//
// RFC 6238 §1.2 makes HMAC-SHA-1 the default for TOTP and RFC 4226 §5.3
// defines HOTP over it, so a default build keeps SHA-1 — it is what mainstream
// authenticator apps enroll with.
const defaultAlgorithm = AlgorithmSHA1

// checkAlgorithmSupported reports whether this build can execute the digest.
// Outside a FIPS-140-only build every algorithm the package accepts is
// executable; algorithm_fips140only.go is the counterpart.
func checkAlgorithmSupported(Algorithm) error { return nil }

// checkSecretSupported reports whether this build can key HMAC with a secret
// of the given strength. It takes a bit count rather than the key so no raw
// key material crosses the boundary.
//
// Outside a FIPS-140-only build there is no minimum beyond the package's
// existing "must be valid base32" rule, which is what callers with secrets
// enrolled against RFC 4226 §4 R6's 128-bit recommendation — or the shorter
// ones some provisioning tools emit — already rely on.
func checkSecretSupported(int) error { return nil }
