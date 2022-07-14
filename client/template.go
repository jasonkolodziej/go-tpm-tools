package client

import (
	"crypto/sha256"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const (
	defaultDevIdAuth = false
)

// Calculations from Credential_Profile_EK_V2.0, section 2.1.5.3 - authPolicy
func defaultEKAuthPolicy() []byte {
	buf, err := tpmutil.Pack(tpm2.CmdPolicySecret, tpm2.HandleEndorsement)
	if err != nil {
		panic(err)
	}
	digest1 := sha256.Sum256(append(make([]byte, 32), buf...))
	// We would normally append the policy buffer to digest1, but the
	// policy buffer is empty for the default Auth Policy.
	digest2 := sha256.Sum256(digest1[:])
	return digest2[:]
}

func defaultEKAttributes() tpm2.KeyProp {
	// The EK is a storage key that must use session-based authorization.
	return (tpm2.FlagStorageDefault | tpm2.FlagAdminWithPolicy) & ^tpm2.FlagUserWithAuth
}

func defaultSRKAttributes() tpm2.KeyProp {
	// FlagNoDA doesn't do anything (as the AuthPolicy is nil). However, this is
	// what Windows does, and we don't want to conflict.
	return tpm2.FlagStorageDefault | tpm2.FlagNoDA
}

func defaultSymScheme() *tpm2.SymScheme {
	return &tpm2.SymScheme{
		Alg:     tpm2.AlgAES,
		KeyBits: 128,
		Mode:    tpm2.AlgCFB,
	}
}

func defaultRSAParams() *tpm2.RSAParams {
	return &tpm2.RSAParams{
		Symmetric:  defaultSymScheme(),
		KeyBits:    2048,
		ModulusRaw: make([]byte, 256), // public.unique must be all zeros
	}
}

func defaultECCParams() *tpm2.ECCParams {
	return &tpm2.ECCParams{
		Symmetric: defaultSymScheme(),
		CurveID:   tpm2.CurveNISTP256,
		Point: tpm2.ECPoint{
			XRaw: make([]byte, 32),
			YRaw: make([]byte, 32),
		},
	}
}

// DefaultEKTemplateRSA returns the default Endorsement Key (EK) template as
// specified in Credential_Profile_EK_V2.0, section 2.1.5.1 - authPolicy.
// https://trustedcomputinggroup.org/wp-content/uploads/Credential_Profile_EK_V2.0_R14_published.pdf
func DefaultEKTemplateRSA() tpm2.Public {
	return tpm2.Public{
		Type:          tpm2.AlgRSA,
		NameAlg:       tpm2.AlgSHA256,
		Attributes:    defaultEKAttributes(),
		AuthPolicy:    defaultEKAuthPolicy(),
		RSAParameters: defaultRSAParams(),
	}
}

// DefaultEKTemplateECC returns the default Endorsement Key (EK) template as
// specified in Credential_Profile_EK_V2.0, section 2.1.5.2 - authPolicy.
// https://trustedcomputinggroup.org/wp-content/uploads/Credential_Profile_EK_V2.0_R14_published.pdf
func DefaultEKTemplateECC() tpm2.Public {
	return tpm2.Public{
		Type:          tpm2.AlgECC,
		NameAlg:       tpm2.AlgSHA256,
		Attributes:    defaultEKAttributes(),
		AuthPolicy:    defaultEKAuthPolicy(),
		ECCParameters: defaultECCParams(),
	}
}

// AKTemplateRSA returns a potential Attestation Key (AK) template.
// This is very similar to DefaultEKTemplateRSA, except that this will be a
// signing key instead of an encrypting key.
func AKTemplateRSA() tpm2.Public {
	return tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagSignerDefault,
		RSAParameters: &tpm2.RSAParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgRSASSA,
				Hash: tpm2.AlgSHA256,
			},
			KeyBits: 2048,
		},
	}
}

// AKTemplateECC returns a potential Attestation Key (AK) template.
// This is very similar to DefaultEKTemplateECC, except that this will be a
// signing key instead of an encrypting key.
func AKTemplateECC() tpm2.Public {
	params := defaultECCParams()
	params.Symmetric = nil
	params.Sign = &tpm2.SigScheme{
		Alg:  tpm2.AlgECDSA,
		Hash: tpm2.AlgSHA256,
	}
	return tpm2.Public{
		Type:          tpm2.AlgECC,
		NameAlg:       tpm2.AlgSHA256,
		Attributes:    tpm2.FlagSignerDefault,
		ECCParameters: params,
	}
}

// SRKTemplateRSA returns a standard Storage Root Key (SRK) template.
// This is based upon the advice in the TCG's TPM v2.0 Provisioning Guidance.
func SRKTemplateRSA() tpm2.Public {
	return tpm2.Public{
		Type:          tpm2.AlgRSA,
		NameAlg:       tpm2.AlgSHA256,
		Attributes:    defaultSRKAttributes(),
		RSAParameters: defaultRSAParams(),
	}
}

// SRKTemplateECC returns a standard Storage Root Key (SRK) template.
// This is based upon the advice in the TCG's TPM v2.0 Provisioning Guidance.
func SRKTemplateECC() tpm2.Public {
	return tpm2.Public{
		Type:          tpm2.AlgECC,
		NameAlg:       tpm2.AlgSHA256,
		Attributes:    defaultSRKAttributes(),
		ECCParameters: defaultECCParams(),
	}
}

// DevIdKeyTemplate is a signing key per:
// "TPM 2.0 Keys for Device Identity and Attestation" - Table 1 & Section 7.3.4
// "TCG TPM v2.0 Provisioning Guidance" - Section 7.4.2.1
func defaultDevIdAttributes(withUserAuth *bool) tpm2.KeyProp {
	var kProp = (tpm2.FlagSignerDefault &^ tpm2.FlagRestricted) | tpm2.FlagAdminWithPolicy
	if withUserAuth == nil {
		*withUserAuth = defaultDevIdAuth
	}
	if *withUserAuth {
		return kProp
	}
	return kProp &^ tpm2.FlagUserWithAuth
}

// IDevIdIak from "TPM 2.0 Keys for Device Identity and Attestation"
// Section 7.3.1 (Table 2) & 7.3.4.2 (Table 4)
func IDevIdIak(alg tpm2.Algorithm, createIak bool, withUserAuth *bool) tpm2.Public {
	const (
		devId = "DEVID"
		iak   = "IAK"
	)
	var temp = tpm2.Public{}
	var mod = []byte(devId)
	var nMod []byte
	if createIak {
		mod = []byte(iak)
	}
	switch alg {
	case tpm2.AlgRSA:
	case tpm2.AlgSHA256:
		nMod = make([]byte, 256)
		temp.Type = tpm2.AlgRSA
		temp.NameAlg = tpm2.AlgSHA256
		temp.RSAParameters = &tpm2.RSAParams{
			KeyBits: 2048,
		}
	case tpm2.AlgECC:
		temp.Type = tpm2.AlgECC
		temp.ECCParameters = &tpm2.ECCParams{
			Sign: &tpm2.SigScheme{Alg: tpm2.AlgECDSA}}
		alg &^= tpm2.AlgECC
	case tpm2.AlgSHA384:
		nMod = make([]byte, 384)
		//temp.Type = tpm2.AlgECC
		temp.NameAlg = tpm2.AlgSHA384
		temp.ECCParameters.CurveID = tpm2.CurveNISTP384
		//temp.ECCParameters = &tpm2.ECCParams{
		//	Symmetric: &tpm2.SymScheme{Alg: tpm2.AlgECDSA},
		//	CurveID:   tpm2.CurveNISTP384,
		//}
	case tpm2.AlgSHA512:
		nMod = make([]byte, 512)
		temp.Type = tpm2.AlgECC
		temp.NameAlg = tpm2.AlgSHA512
		temp.ECCParameters.CurveID = tpm2.CurveNISTP521
		//temp.ECCParameters = &tpm2.ECCParams{
		//	Sign:    &tpm2.SigScheme{Alg: tpm2.AlgECDSA},
		//	CurveID: tpm2.CurveNISTP521,
		//}
	default:
		return temp
	}
	temp.Attributes = defaultDevIdAttributes(withUserAuth)
	for i, c := range mod {
		nMod[i] = c
	}
	if temp.RSAParameters != nil {
		temp.RSAParameters.ModulusRaw = nMod
	} else {
		l := len(nMod) / 8
		temp.ECCParameters.Point = tpm2.ECPoint{
			XRaw: nMod[0:l],
			YRaw: nMod[(l + 1):],
		}
	}
	return temp
}

// defaultIDevIdIakNvPolicyAttrs from "TPM 2.0 Keys for Device Identity and Attestation"
// Section 7.3.5.1 (Table 9)
func defaultIDevIdIakNvPolicyAttrs() tpm2.NVAttr {
	return tpm2.AttrNoDA |
		tpm2.AttrPolicyWrite | tpm2.AttrWriteAll | tpm2.AttrWritten |
		tpm2.AttrPPRead | tpm2.AttrOwnerRead | tpm2.AttrAuthRead | tpm2.AttrPolicyRead
}

// devIdNvHandle defined by "TPM 2.0 Keys for Device Identity and Attestation" Section 7.3.2 IDevID/IAK Policy NV Indices for Recoverable Keys
type devidNvHandle = tpmutil.Handle

const (
	Sha256SigningKey devidNvHandle = 0x01C90010
	Sha256Ak         devidNvHandle = 0x01C90018
	SHA384SigningKey devidNvHandle = 0x01C90011
	SHA384Ak         devidNvHandle = 0x01C90019
	Sha512SigningKey devidNvHandle = 0x01C90012
	Sha512Ak         devidNvHandle = 0x01C9001A
	Sm3256SigningKey devidNvHandle = 0x01C90013
	Sm3256Ak         devidNvHandle = 0x01C9001B
)

func IDevIdIakNvPolicy(algorithm tpm2.Algorithm, nvHandle devidNvHandle) tpm2.NVPublic {
	var dataSize uint16 = 0
	switch algorithm {
	case tpm2.AlgSHA256:
		dataSize = 32
	case tpm2.AlgSHA384:
		dataSize = 50
	case tpm2.AlgSHA512:
		dataSize = 66
	default:
		return tpm2.NVPublic{}
	}
	return tpm2.NVPublic{
		NVIndex:    nvHandle,
		NameAlg:    algorithm,
		Attributes: defaultIDevIdIakNvPolicyAttrs(),
		DataSize:   dataSize,
	}
}
