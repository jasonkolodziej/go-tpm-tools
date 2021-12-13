package client

import (
	"bytes"
	"crypto"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"io"
)

// maxBytesBufferSize sets a sane upper bound on the size of a U32Bytes
// buffer. This limit exists to prevent a maliciously large size prefix
// from resulting in a massive memory allocation, potentially causing
// an OOM condition on the system.
// We expect no buffer from a TPM to approach 1Mb in size.
const maxBytesBufferSize = 1024 * 1024 // 1Mb.

const maxDigestBufferSize = 1024 // 1024 octet, but implementation dependant

type (
	DataToHash = []byte
	Digest     = []byte
	Ticket     = tpm2.Ticket
	/*HashResolver returns at minimum the cryptographic hash in Hash.
	Upon presence of io.ReadWriter:
		- with Hash func, will attempt to invoke the TPM to perform crypto.Hash
		- with HashWithSequencing func, will attempt the same as Hash func along with determining if the hash algorithm,
			crypto.Hash, is a tpm2.Algorithm that hash implemented hashing functionality,
			thus starting a hash sequence is started.
			If tpm2.Algorithm is determined as TPM_ALG_NULL, then an TPM event sequence is started.*/
	HashResolver = func() (hashType *crypto.Hash, rw io.ReadWriter)
)

func ByteSliceToBuffer(data DataToHash) *bytes.Buffer { return bytes.NewBuffer(data) }
func feedDataByChunks(dataBuffer *bytes.Buffer) DataToHash {
	return dataBuffer.Next(maxDigestBufferSize)
}

/*Hash uses HashResolver to determine how to hash outside data, DataToHash, either with OS Library or TPM (tpm2.Hash).
-	With TPM,
	- for Single Hash, tpmutil.Handle shall not = nil
	- for Sequenced Hash, tpmutil.Handle, sequenceAuthorization shall not = nil
Returns a Ticket (along with Digest of DataToHash)
-	With OS Library, tpmutil.Handle can be nil thus Returns Digest and nil Ticket
- or error*/
func Hash(data DataToHash, resolver HashResolver,
	hierarchyHandle *tpmutil.Handle, sequenceAuthorization *string) (Digest, *Ticket, error) {
	h, device := resolver()
	// perform sequence hashing w/ TPM
	if sequenceAuthorization != nil {
		return HashWithSequencing(data, resolver, *sequenceAuthorization, hierarchyHandle)
	}
	// try using TPM
	if device != nil && hierarchyHandle != nil {
		var alg tpm2.Algorithm
		var err error
		if h != nil {
			alg, err = tpm2.HashToAlgorithm(*h)
			if err != nil {
				return nil, nil, err
			}
		} else {
			alg = tpm2.AlgNull
		}
		if err != nil {
			return nil, nil, err
		}
		// perform normal hashing - this assumes variable data's size has been accounted for
		return tpm2.Hash(device, alg, data, *hierarchyHandle)
	}
	// OS Library
	alg := h.New()
	_, err := alg.Write(data)
	if err != nil {
		return nil, nil, err
	}
	return alg.Sum(nil), nil, nil
}

/*HashWithSequencing uses HashResolver to determine how to hash outside data, DataToHash,
to the TPM (tpm2.HashSequenceStart, tpm2.SequenceUpdate, tpm2.SequenceComplete).

-	With TPM for Sequenced Hash, hierarchyHandle tpmutil.Handle, sequenceAuthorization shall not = nil.
DataToHash is transformed into bytes.Buffer, with ByteSliceToBuffer,
to sequentially feed maxDigestBufferSize to the TPM.

	Returns a Ticket (along with Digest of DataToHash)

- or error*/
func HashWithSequencing(data DataToHash, resolver HashResolver,
	sequenceAuthorization string, hierarchyHandle *tpmutil.Handle) (Digest, *Ticket, error) {
	// convert data into buffer
	var sequenceHandle tpmutil.Handle
	var alg tpm2.Algorithm
	var err error
	dataBuffer := ByteSliceToBuffer(data)
	h, device := resolver()
	if h != nil {
		alg, err = tpm2.HashToAlgorithm(*h)
		if err != nil {
			return nil, nil, err
		}
	} else {
		// enforces AlgNull
		alg = tpm2.AlgNull
	}
	// TPM
	if device != nil && hierarchyHandle != nil {
		sequenceHandle, err = tpm2.HashSequenceStart(device, sequenceAuthorization, alg)
		if err != nil {
			return nil, nil, err
		}
	}
	// iterate through buffer until empty
	for k := true; k; k = dataBuffer.Len() > 0 {
		err = tpm2.SequenceUpdate(device, sequenceAuthorization, sequenceHandle, dataBuffer.Next(maxDigestBufferSize))
		if err != nil {
			return nil, nil, err
		}
	}
	return tpm2.SequenceComplete(device, sequenceAuthorization, sequenceHandle, *hierarchyHandle, nil)
}

/*EventWithSequencing records event data in sequence, differs between HashWithSequencing by invoking
tpm2.EventSequenceComplete.

If pcrHandle references a PCR and not tpm2.AlgNull or nil, then the returned digest list is processed in the same
manner as the digest list input parameter to PCRExtend() with the pcrHandle in each bank extended with the
associated digest value.*/
func EventWithSequencing(data DataToHash, resolver HashResolver,
	sequenceAuthorization, pcrAuthorization string, pcrHandle tpmutil.Handle) ([]*tpm2.HashValue, error) {
	// convert data into buffer
	var sequenceHandle tpmutil.Handle
	var alg tpm2.Algorithm
	var err error
	dataBuffer := ByteSliceToBuffer(data)
	h, device := resolver()
	// TODO: inspect for event sequence
	if h != nil {
		alg, err = tpm2.HashToAlgorithm(*h)
		if err != nil {
			return nil, err
		}
	} else {
		// enforces AlgNull
		alg = tpm2.AlgNull
	}
	// TPM
	if device != nil {
		sequenceHandle, err = tpm2.HashSequenceStart(device, sequenceAuthorization, alg)
		if err != nil {
			return nil, err
		}
	}
	// iterate through buffer until empty
	for k := true; k; k = dataBuffer.Len() > 0 {
		err = tpm2.SequenceUpdate(device, sequenceAuthorization, sequenceHandle, dataBuffer.Next(maxDigestBufferSize))
		if err != nil {
			return nil, err
		}
	}
	return tpm2.EventSequenceComplete(device, pcrAuthorization, sequenceAuthorization, pcrHandle, sequenceHandle, nil)
}
