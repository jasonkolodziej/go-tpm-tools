package server

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"

	// Rather than crypto/x509 as ct allows disabling critical extension checks.
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/go-tpm/tpm2"
	"github.com/jasonkolodziej/go-tpm-tools/internal"
	pb "github.com/jasonkolodziej/go-tpm-tools/proto/attest"
	tpmpb "github.com/jasonkolodziej/go-tpm-tools/proto/tpm"
	"google.golang.org/protobuf/proto"
)

// The hash algorithms we support, in their preferred order of use.
var supportedHashAlgs = []tpm2.Algorithm{
	tpm2.AlgSHA512, tpm2.AlgSHA384, tpm2.AlgSHA256, tpm2.AlgSHA1,
}

// VerifyOpts allows for customizing the functionality of VerifyAttestation.
type VerifyOpts struct {
	// The nonce used when calling client.Attest
	Nonce []byte
	// Trusted public keys that can be used to directly verify the key used for
	// attestation. This option should be used if you already know the AK, as
	// it provides the highest level of assurance.
	TrustedAKs []crypto.PublicKey
	// Allow attestations to be verified using SHA-1. This defaults to false
	// because SHA-1 is a weak hash algorithm with known collision attacks.
	// However, setting this to true may be necessary if the client only
	// supports the legacy event log format. This is the case on older Linux
	// distributions (such as Debian 10).
	AllowSHA1 bool
	// A collection of trusted root CAs that are used to sign AK certificates.
	// The TrustedAKs are used first, followed by TrustRootCerts and
	// IntermediateCerts.
	// Adding a specific TPM manufacturer's root and intermediate CAs means all
	// TPMs signed by that CA will be trusted.
	TrustedRootCerts  *x509.CertPool
	IntermediateCerts *x509.CertPool
}

// VerifyAttestation performs the following checks on an Attestation:
//    - the AK used to generate the attestation is trusted (based on VerifyOpts)
//    - the provided signature is generated by the trusted AK public key
//    - the signature signs the provided quote data
//    - the quote data starts with TPM_GENERATED_VALUE
//    - the quote data is a valid TPMS_QUOTE_INFO
//    - the quote data was taken over the provided PCRs
//    - the provided PCR values match the quote data internal digest
//    - the provided opts.Nonce matches that in the quote data
//    - the provided eventlog matches the provided PCR values
//
// After this, the eventlog is parsed and the corresponding MachineState is
// returned. This design prevents unverified MachineStates from being used.
func VerifyAttestation(attestation *pb.Attestation, opts VerifyOpts) (*pb.MachineState, error) {
	// Verify the AK
	akPubArea, err := tpm2.DecodePublic(attestation.GetAkPub())
	if err != nil {
		return nil, fmt.Errorf("failed to decode AK public area: %w", err)
	}
	akPubKey, err := akPubArea.Key()
	if err != nil {
		return nil, fmt.Errorf("failed to get AK public key: %w", err)
	}
	if err := checkAkTrusted(akPubKey, opts); err != nil {
		if err := validateAkCert(attestation.AkCert, opts.IntermediateCerts, opts.TrustedRootCerts); err != nil {
			return nil, fmt.Errorf("failed to validate attestation key: AKPub is untrusted and %v", err)
		}
	}

	// Verify the signing hash algorithm
	signHashAlg, err := internal.GetSigningHashAlg(akPubArea)
	if err != nil {
		return nil, fmt.Errorf("bad AK public area: %w", err)
	}
	if err = checkHashAlgSupported(signHashAlg, opts); err != nil {
		return nil, fmt.Errorf("in AK public area: %w", err)
	}

	// Attempt to replay the log against our PCRs in order of hash preference
	var lastErr error
	for _, quote := range supportedQuotes(attestation.GetQuotes()) {
		// Verify the Quote
		if err = internal.VerifyQuote(quote, akPubKey, opts.Nonce); err != nil {
			lastErr = fmt.Errorf("failed to verify quote: %w", err)
			continue
		}

		// Parse event logs and replay the events against the provided PCRs
		pcrs := quote.GetPcrs()
		state, err := parsePCClientEventLog(attestation.GetEventLog(), pcrs)
		if err != nil {
			lastErr = fmt.Errorf("failed to validate the PCClient event log: %w", err)
			continue
		}

		celState, err := parseCanonicalEventLog(attestation.GetCanonicalEventLog(), pcrs)
		if err != nil {
			lastErr = fmt.Errorf("failed to validate the Canonical event log: %w", err)
			continue
		}

		proto.Merge(celState, state)

		// Verify the PCR hash algorithm. We have this check here (instead of at
		// the start of the loop) so that the user gets a "SHA-1 not supported"
		// error only if allowing SHA-1 support would actually allow the log
		// to be verified. This makes debugging failed verifications easier.
		pcrHashAlg := tpm2.Algorithm(pcrs.GetHash())
		if err = checkHashAlgSupported(pcrHashAlg, opts); err != nil {
			lastErr = fmt.Errorf("when verifying PCRs: %w", err)
			continue
		}

		return celState, nil
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("attestation does not contain a supported quote")
}

func pubKeysEqual(k1 crypto.PublicKey, k2 crypto.PublicKey) bool {
	switch key := k1.(type) {
	case *rsa.PublicKey:
		return key.Equal(k2)
	case *ecdsa.PublicKey:
		return key.Equal(k2)
	default:
		return false
	}
}

// Checks if the provided AK public key can be trusted
func checkAkTrusted(ak crypto.PublicKey, opts VerifyOpts) error {
	if len(opts.TrustedAKs) == 0 {
		return fmt.Errorf("no mechanism for AK verification provided")
	}

	// Check against known AKs
	for _, trusted := range opts.TrustedAKs {
		if pubKeysEqual(ak, trusted) {
			return nil
		}
	}
	return fmt.Errorf("AK public key is not trusted")
}

func validateAkCert(akCertBytes []byte, intermediates *x509.CertPool, roots *x509.CertPool) error {
	if len(akCertBytes) == 0 {
		return errors.New("AKCert is empty")
	}

	akCert, err := x509.ParseCertificate(akCertBytes)
	if err != nil {
		return fmt.Errorf("failed to parse AKCert: %v", err)
	}

	if _, err := akCert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		// x509 (both ct and crypto) marks the SAN extension unhandled if SAN
		// does not parse any of DNSNames, EmailAddresses, IPAddresses, or URIs.
		// https://cs.opensource.google/go/go/+/master:src/crypto/x509/parser.go;l=668-678
		DisableCriticalExtensionChecks: true,
		// The default key usage (ExtKeyUsageServerAuth) is not appropriate for
		// an Attestation Key: ExtKeyUsage of
		// - https://oidref.com/2.23.133.8.1
		// - https://oidref.com/2.23.133.8.3
		// https://pkg.go.dev/crypto/x509#VerifyOptions
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsage(x509.ExtKeyUsageAny)},
	}); err != nil {
		return fmt.Errorf("failed to verify AKCert against trusted roots: %v", err)
	}
	return nil
}

func checkHashAlgSupported(hash tpm2.Algorithm, opts VerifyOpts) error {
	if hash == tpm2.AlgSHA1 && !opts.AllowSHA1 {
		return fmt.Errorf("SHA-1 is not allowed for verification (set VerifyOpts.AllowSHA1 to true to allow)")
	}
	for _, alg := range supportedHashAlgs {
		if hash == alg {
			return nil
		}
	}
	return fmt.Errorf("unsupported hash algorithm: %v", hash)
}

// Retrieve the supported quotes in order of hash preference
func supportedQuotes(quotes []*tpmpb.Quote) []*tpmpb.Quote {
	out := make([]*tpmpb.Quote, 0, len(quotes))
	for _, alg := range supportedHashAlgs {
		for _, quote := range quotes {
			if tpm2.Algorithm(quote.GetPcrs().GetHash()) == alg {
				out = append(out, quote)
				break
			}
		}
	}
	return out
}
