//go:build !fips140only

package otp

// The algorithms the suite exercises, and the algorithm it uses where the
// choice of digest is incidental to what is being tested.
//
// RFC 6238 §1.2 makes HMAC-SHA-1 the default for TOTP and every mainstream
// authenticator app implements it, so a default build tests SHA-1 first. Go's
// fips140=only mode rejects HMAC over anything but SHA-2/SHA-3, so the
// fips140only build swaps these for the approved digests
// (see algorithm_fips140only_test.go and docs/fips.md).
const testAlgorithm = AlgorithmSHA1

var testAlgorithms = []Algorithm{AlgorithmSHA1, AlgorithmSHA256, AlgorithmSHA512}
