package tpm2

import (
	"context"
	"errors"
	"fmt"
)

// Handle represents a TPM object handle for sealed data.
type Handle uint32

// TPMSession represents an active TPM connection capable of unsealing data.
type TPMSession interface {
	// Unseal attempts to unseal data from the TPM using the provided handle and password.
	// The TPM will automatically verify PCR policy during the unseal operation.
	Unseal(ctx context.Context, handle Handle, password string) ([]byte, error)
	// Close terminates the TPM session.
	Close(ctx context.Context) error
}

// TPMProvider abstracts creation of TPM sessions from configuration.
type TPMProvider interface {
	// Open establishes a connection to the TPM device and returns a session.
	Open(ctx context.Context, cfg Config) (TPMSession, error)
}

// Common errors returned by the TPM authenticator.
var (
	// ErrTPMUnavailable indicates the TPM device is not accessible.
	ErrTPMUnavailable = errors.New("tpm2: device unavailable")
	// ErrInvalidPassword indicates the supplied password was rejected during unsealing.
	ErrInvalidPassword = errors.New("tpm2: invalid authorization")
	// ErrPCRMismatch indicates PCR policy validation failed during unseal.
	ErrPCRMismatch = errors.New("tpm2: pcr policy validation failed")
	// ErrNilAuthenticator indicates a nil authenticator was used.
	ErrNilAuthenticator = errors.New("tpm2: authenticator is nil")
	// ErrEmptyPassword indicates an empty password was provided.
	ErrEmptyPassword = errors.New("tpm2: password must not be empty")
	// ErrInvalidHandle indicates an invalid sealed object handle.
	ErrInvalidHandle = errors.New("tpm2: invalid sealed object handle")
	// errSystemProviderUnavailable indicates no system provider is configured.
	errSystemProviderUnavailable = errors.New("tpm2: system provider unavailable; configure a TPM provider")
)

// Config supplies the parameters required to locate and unseal data from a TPM 2.0 device.
type Config struct {
	// DevicePath is the path to the TPM device (e.g., "/dev/tpm0", "/dev/tpmrm0").
	DevicePath string
	// SealedHandle is the TPM handle containing the sealed data.
	// This is typically a persistent handle (0x81xxxxxx) or transient handle.
	SealedHandle Handle
	// PCRSelection specifies which PCR registers must match for unsealing.
	// PCR values 0-23 are typically available on TPM 2.0 devices.
	PCRSelection []int
	// HashAlgorithm specifies the hash algorithm for PCR banks.
	// Supported values: "SHA1", "SHA256" (default), "SHA384", "SHA512".
	// If empty, defaults to "SHA256".
	HashAlgorithm string
}

// validate checks that the configuration is valid.
func (c Config) validate() error {
	if c.DevicePath == "" {
		return errors.New("tpm2: device path must not be empty")
	}
	if c.SealedHandle == 0 {
		return errors.New("tpm2: sealed handle must be specified")
	}
	if len(c.PCRSelection) == 0 {
		return errors.New("tpm2: at least one PCR must be selected")
	}

	// Validate PCR numbers (typically 0-23 for TPM 2.0)
	for _, pcr := range c.PCRSelection {
		if pcr < 0 || pcr > 23 {
			return fmt.Errorf("tpm2: PCR %d is invalid; must be between 0 and 23", pcr)
		}
	}

	// Validate hash algorithm if specified
	if c.HashAlgorithm != "" {
		switch c.HashAlgorithm {
		case "SHA1", "SHA256", "SHA384", "SHA512":
			// Valid algorithms
		default:
			return fmt.Errorf("tpm2: unsupported hash algorithm: %s", c.HashAlgorithm)
		}
	}

	return nil
}

var systemTPMProvider TPMProvider

// SetSystemTPMProvider installs the default TPM provider used when callers
// pass nil to NewAuthenticator. Primarily useful for tests or wiring concrete
// implementations from hosting applications.
func SetSystemTPMProvider(p TPMProvider) {
	systemTPMProvider = p
}

// Authenticator validates credentials by unsealing data from a TPM 2.0 device.
// The unsealing operation automatically validates PCR policy, providing
// hardware-based platform integrity verification.
type Authenticator struct {
	cfg      Config
	provider TPMProvider
}

// NewAuthenticator constructs a TPM 2.0 authenticator using the supplied configuration.
// If provider is nil, the package-level system provider is used.
//
// The authenticator validates platform state by attempting to unseal data that was
// sealed to specific PCR values. If the current platform state (PCR values) matches
// the sealed policy, unsealing succeeds; otherwise it fails with ErrPCRMismatch.
func NewAuthenticator(cfg Config, provider TPMProvider) (*Authenticator, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if provider == nil {
		if systemTPMProvider == nil {
			return nil, errSystemProviderUnavailable
		}
		provider = systemTPMProvider
	}
	return &Authenticator{cfg: cfg, provider: provider}, nil
}

// Authenticate attempts to unseal data from the TPM using the provided password.
// The TPM automatically validates PCR policy during unsealing, providing hardware-based
// verification that the platform is in a trusted state.
//
// Returns ErrPCRMismatch if the current PCR values don't match the sealed policy,
// ErrInvalidPassword if the password is incorrect, or other errors for TPM failures.
func (a *Authenticator) Authenticate(ctx context.Context, password string) (err error) {
	if a == nil {
		return ErrNilAuthenticator
	}
	if password == "" {
		return ErrEmptyPassword
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	session, err := a.provider.Open(ctx, a.cfg)
	if err != nil {
		return err
	}

	defer func() {
		if cerr := session.Close(ctx); cerr != nil {
			if err != nil {
				err = errors.Join(err, cerr)
			} else {
				err = cerr
			}
		}
	}()

	// Attempt to unseal the data. The TPM will automatically verify:
	// 1. The password/authorization value is correct
	// 2. The PCR values match the sealed policy
	_, err = session.Unseal(ctx, a.cfg.SealedHandle, password)
	return err
}
