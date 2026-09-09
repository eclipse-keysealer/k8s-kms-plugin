// SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
// SPDX-License-Identifier: MIT

package providers

import (
	"context"
	"crypto"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"

	"sync"

	"github.com/eclipse-keypont/crypto11/v2"
	"github.com/eclipse-keypont/gose"
	"github.com/eclipse-keypont/gose/hsm"
	"github.com/eclipse-keypont/gose/jose"
	pkcs11 "github.com/eclipse-keypont/pkcs11-go/cryptoki"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	k8skmsv2 "k8s.io/kms/apis/v2"

	"github.com/eclipse-keysealer/k8s-kms-plugin/pkg/logging"
)

// Algorithm sentinels used in P11.algorithmFamily for routing. Values match the user-facing
// --algorithm-family flag slugs so serve.go can cast directly without a mapping function.
// The actual jose algorithm constant used in JWE operations may differ (e.g. AlgAESGCM
// dispatches to AlgA128/192/256GCM based on the HSM key's CKA_VALUE_LEN).
const (
	// AlgAESGCM routes to AES-GCM; key size is auto-detected from the HSM key.
	AlgAESGCM jose.Alg = "aes-gcm"
	// AlgAESCBC routes to AES-CBC + HMAC; the JWE uses jose.AlgA256CBC internally.
	AlgAESCBC jose.Alg = "aes-cbc"
	// AlgRSAOAEP routes to RSA-OAEP; the JWE uses jose.AlgRSAOAEP internally.
	AlgRSAOAEP jose.Alg = "rsa-oaep"
	// AlgMLKEM routes to ML-KEM hybrid encryption; variant is negotiated from the HSM key.
	AlgMLKEM jose.Alg = "ml-kem"
)

const (
	// AlgorithmFamilyAnnotationKey is the KMS v2 EncryptResponse.Annotations key carrying the
	// plugin's active --algorithm-family value (e.g. "aes-gcm", "ml-kem") as informational
	// metadata. Set on every EncryptResponse regardless of algorithm family.
	AlgorithmFamilyAnnotationKey = "algorithm-family.k8s-kms-plugin.keysealer.eclipse.org"
)

// putAlgorithmFamily records the active --algorithm-family value on resp.Annotations.
func putAlgorithmFamily(resp *k8skmsv2.EncryptResponse, alg jose.Alg) {
	if resp.Annotations == nil {
		resp.Annotations = map[string][]byte{}
	}
	resp.Annotations[AlgorithmFamilyAnnotationKey] = []byte(alg)
}

// IsPKCS11AuthenticationError returns true
// if further attempts to log in will risk causing the
// device to be locked.
func IsPKCS11AuthenticationError(err error) bool {
	if err == nil {
		return false
	}

	var pkErr pkcs11.Error
	ok := errors.As(errors.Unwrap(err), &pkErr)
	if !ok {
		return false
	}

	switch pkErr {
	case pkcs11.CKR_PIN_INCORRECT:
		return true
	default:
		return false
	}
}

// P11 is a struct representing a P11 provider, which handles encryption and decryption
// operations using a Hardware Security Module (HSM). It manages keys, contexts, and
// encryption algorithms necessary for secure cryptographic operations within the KMS plugin.
//
// Active Fields: the actual keys being used in StatusResponse and EncryptResponse.
//
// KEK Key Rotation Fields:,old keys used for Decryption of old ciphertext during a key rotation.
// See: https://kubernetes.io/docs/tasks/administer-cluster/kms-provider/#developing-a-kms-plugin-gRPC-server-notes-kms-v2
type P11 struct {
	// Starting with [KMS v0.34.0](https://github.com/kubernetes/kms/tree/v0.34.0/apis/v2), the KMS maintainers stoped to use https://github.com/gogo/protobuf to generate protobuf files, as it is deprecated.
	// KMS v0.34.0 and later uses official https://github.com/protocolbuffers/protobuf-go. This demands that the gRPC server embeds UnimplementedKeyManagementServiceServer to automatically satisfy method mustEmbedUnimplementedKeyManagementServiceServer()
	k8skmsv2.UnimplementedKeyManagementServiceServer

	// mu guards encryptors, decryptors, and oldDecryptors against concurrent reads and writes.
	mu sync.RWMutex

	// active KEK parameters
	createKey       bool                         // Indicates whether the k8s-kms-plugin should create a new key. TODO: explain the use case of when should the k8s-kms-plugin create the key, or create a new cobra command
	config          *crypto11.Config             // Active configuration for the crypto11 library
	ctx             *crypto11.Context            // Active cryptographic context for key operations
	encryptors      map[string]gose.JweEncryptor // Active Map of JWE encryptors used for encryption operations
	decryptors      map[string]gose.JweDecryptor // Active Map of JWE decryptors used for decryption operations
	kekCkaID        []byte                       // Active Key Encryption Key KEK Identifier & CKA_ID
	kekCkaLabel     string                       // Active KEK CKA_LABEL utf8
	hmacCkaID       []byte                       // Active HMAC key CKA_ID for AES-CBC + HMAC
	hmacCkaLabel    string                       // Active HMAC key CKA_LABEL utf8 for AES-CBC + HMAC
	algorithmFamily jose.Alg                     // The active cryptographic algorithm family being used

	// KEK Key rotation feature for KMS v2
	oldConfig *crypto11.Config  // for key rotation
	oldCtx    *crypto11.Context // for key rotation
	// no encryptors since the old KEK keys are used for decryption only
	oldDecryptors      map[string]gose.JweDecryptor // for key rotation
	oldKekCkaID        []byte                       // Key Encryption Key KEK Identifier & CKA_ID of old KEK being rotated
	oldKekCkaLabel     string                       // CKA_LABEL utf8 of old KEK being rotated
	oldHmacCkaID       []byte                       // CKA_ID of old HMAC key being rotated
	oldHmacCkaLabel    string                       // CKA_LABEL utf8 of old HMAC key being rotated
	oldAlgorithmFamily jose.Alg                     // algorithm family of old KEK being rotated
}

// NewP11 creates a new P11 instance.
//
// The P11 instance is configured with the given crypto11.Config.
//
// The createKey argument is a boolean that indicates whether the P11 instance
// should create a default key with the given label. TODO: explain the use case
// when this would be needed, eventually move this to a new command.
//
// The kekkeyid argument is the Key Encryption Key (KEK) identifier.
// This is the PKCS #11 CKA_ID.
//
// The k8sKekLabel argument is the label of the default key.
// This is the PKCS #11 CKA_LABEL.
//
// The hmacKeyLabel argument is the label of the HMAC key, for AES-CBC + HMAC.
//
// The algorithm argument specify which algorithm to use, symmetric or
// asymmetric.
//
// The function returns a pointer to the P11 instance and an error value. If
// the error value is not nil, the P11 instance is not valid and should not
// be used.
func NewP11(
	// active KEK parameters
	config *crypto11.Config,
	createKey bool,
	kekkeyid string,
	k8sKekLabel string,
	hmacKeyLabel string,
	hmacCkaID string,
	algorithm jose.Alg,

	// key rotation
	isKeyRotation bool,
	oldConfig *crypto11.Config,
	oldKekkeyid string,
	oldKekCkaLabel string,
	oldHmacKeyLabel string,
	oldHmacCkaID string,
	oldAlgorithm jose.Alg,
) (p *P11, err error) {
	p = &P11{
		// active KEK parameters
		config:          config,
		createKey:       createKey,
		algorithmFamily: algorithm,

		// only in case of key rotation
		oldConfig:          oldConfig,
		oldAlgorithmFamily: oldAlgorithm,
	}

	// Bootstrap the active Pkcs11 device or die
	if p.ctx, err = crypto11.Configure(p.config); err != nil {
		slog.Error("NewP11: failed to configure the active Pkcs11 device", "error", err)
		return
	}

	// Bootstrap the key rotation Pkcs11 device or die
	if isKeyRotation {
		if p.oldCtx, err = crypto11.Configure(p.oldConfig); err != nil {
			slog.Error("NewP11: failed to configure the key rotation Pkcs11 device", "error", err)
			return
		}
	}

	// Case: Attempt to discover KEK ID (CKA_ID) by Key label (CKA_LABEL)
	// From the CLI's user input perspective, the kekkeyid (CKA_ID) and k8sKekLabel (CKA_LABEL)
	// should be marked as MarkFlagsMutuallyExclusive and MarkFlagsOneRequired.
	// This prevent mismatching the two inputs.
	// From kubernetes KMS v2 point of vue, StatusResponse.KeyId, EncryptResponse.KeyId and
	// EncryptRequest.KeyId should use a unique identifier: pkcs11.CKA_ID is a unique identifier.
	// If the user set the k8sKekLabel flag (CKA_LABEL), then the kekkeyid (CKA_ID) is retrieved by
	// the k8sKekLabel.
	// CKA_ID is mandatory to provide the KEK ID to the status requests from Kubernetes' Status
	// Request, so we need to retrieve it mandatorily from the HSM if provided empty.
	// TODO USE SetKekKeyIDString instead of conversions in the method
	p.kekCkaID, p.kekCkaLabel, err = GetKeyIDAndLabel(p, kekkeyid, k8sKekLabel)
	if err != nil {
		return
	}

	// in case the user provide the CKA_ID or the CKA_LABEL of HMAC key
	if p.algorithmFamily == AlgAESCBC {
		p.hmacCkaID, p.hmacCkaLabel, err = GetKeyIDAndLabel(p, hmacCkaID, hmacKeyLabel)
		if err != nil {
			return
		}
	}

	// key rotation
	if isKeyRotation {
		// in case the user provide the OLD CKA_ID or the OLD CKA_LABEL of OLD HMAC key
		if p.oldAlgorithmFamily == AlgAESCBC {
			if oldHmacCkaID == "" && oldHmacKeyLabel != "" { // get id by label
				// old HMAC
				if err = validateCkaLabel(oldHmacKeyLabel); err != nil {
					slog.Error("NewP11: invalid old HMAC CKA_LABEL", "error", err)
					return nil, fmt.Errorf("NewP11: invalid old HMAC CKA_LABEL: %w", err)
				}
				p.oldHmacCkaLabel = oldHmacKeyLabel

				if p.oldHmacCkaID, err = FindCkaAttrByIDOrLabel(p.oldCtx, p.oldAlgorithmFamily, crypto11.CkaId, nil, []byte(p.oldHmacCkaLabel)); err != nil {
					slog.Error("NewP11: failed to find HMAC CKA_ID by label", "error", err)
					return nil, err
				}

			} else if oldHmacCkaID != "" && oldHmacKeyLabel == "" { // get label by id
				if err = p.SetOldHmacKeyIDString(oldHmacCkaID); err != nil {
					slog.Error("NewP11: failed to set old HMAC CKA_ID", "error", err)
					return nil, err
				}

				var labelBuf []byte
				if labelBuf, err = FindCkaAttrByIDOrLabel(p.oldCtx, p.oldAlgorithmFamily, crypto11.CkaLabel, p.oldHmacCkaID, nil); err != nil {
					slog.Error("NewP11: failed to find old HMAC CKA_LABEL by ID", "error", err)
					return nil, err
				}

				p.oldHmacCkaLabel = string(labelBuf)

			} else if oldHmacCkaID == "" && oldHmacKeyLabel == "" {
				slog.Error("NewP11: oldHmacCkaID and oldHmacKeyLabel are both empty, please provide one of them")
				return nil, fmt.Errorf("NewP11: oldHmacCkaID and oldHmacKeyLabel are both empty, please provide one of them")
			} else {
				slog.Error("NewP11: both oldHmacCkaID and oldHmacKeyLabel are provided, please provide only one")
				return nil, fmt.Errorf("NewP11: both oldHmacCkaID and oldHmacKeyLabel are provided, please provide only one")
			}
		}

		// find old KEK ID with LABEL
		if oldKekkeyid == "" && oldKekCkaLabel != "" {
			slog.Log(context.Background(), logging.LevelTrace, "NewP11: kek key id (CKA_ID) is empty. Find CKA_ID by CKA_LABEL", "label", k8sKekLabel)
			if err = validateCkaLabel(oldKekCkaLabel); err != nil {
				slog.Error("NewP11: invalid old KEK CKA_LABEL", "error", err)
				return nil, fmt.Errorf("NewP11: invalid old KEK CKA_LABEL: %w", err)
			}
			p.oldKekCkaLabel = oldKekCkaLabel

			if p.oldKekCkaID, err = FindCkaAttrByIDOrLabel(p.oldCtx, p.oldAlgorithmFamily, crypto11.CkaId, nil, []byte(p.oldKekCkaLabel)); err != nil {
				slog.Error("NewP11: failed to find OLD KEK CKA_ID by label", "error", err)
				return nil, err
			}
		}

		// find old KEK label with ID
		if oldKekkeyid != "" && oldKekCkaLabel == "" {
			slog.Log(context.Background(), logging.LevelTrace, "NewP11: k8sKekLabel (CKA_LABEL) is empty but kekkeyid (CKA_ID) is not empty. Find CKA_LABEL by CKA_ID", "keyId", oldKekkeyid)
			if err = p.SetOldKekKeyIDString(oldKekkeyid); err != nil {
				slog.Error("NewP11: failed to set old KEK CKA_ID", "error", err)
				return nil, err
			}

			var labelBuf []byte
			if labelBuf, err = FindCkaAttrByIDOrLabel(p.oldCtx, p.oldAlgorithmFamily, crypto11.CkaLabel, p.oldKekCkaID, nil); err != nil {
				slog.Error("NewP11: failed to find OLD KEK CKA_LABEL by CKA_ID", "error", err)
				return nil, err
			}
			p.oldKekCkaLabel = string(labelBuf)
		}
	}

	if p.createKey {
		if p.algorithmFamily == AlgMLKEM {
			// ML-KEM key pairs must be provisioned separately on the HSM; auto-create is not supported.
			slog.Warn("NewP11: --auto-create is not supported for ml-kem; ML-KEM key pair must be created separately on the HSM")
		} else {
			// Check if the default key exists - if not, create it
			var foundDefaultDek *crypto11.SecretKey
			if foundDefaultDek, err = p.ctx.FindKey(p.kekCkaID, p.GetKekCkaLabelByteA()); nil != err {
				return
			}
			if nil == foundDefaultDek {
				var newDekUUID uuid.UUID
				if newDekUUID, err = uuid.NewRandom(); nil != err {
					return
				}
				var uuidBytes []byte
				if uuidBytes, err = newDekUUID.MarshalText(); nil != err {
					return
				}
				if _, err = p.ctx.GenerateSecretKeyWithLabel(uuidBytes, p.GetKekCkaLabelByteA(), 256, crypto11.CipherAES); nil != err {
					return
				}
			}
		}
	}
	return
}

// SetKekKeyIDFromBytes sets the internal active KEK CKA_ID from raw bytes.
func (p *P11) SetKekKeyIDFromBytes(keyID []byte) error {
	if keyID == nil {
		return fmt.Errorf("keyID cannot be nil")
	}
	// Raw bytes bypass validateHexKeyID, so check the KMS v2 bound the KeyId must satisfy.
	if err := validateKMSv2KeyID(hex.EncodeToString(keyID)); err != nil {
		slog.Error("SetKekKeyIDFromBytes: CKA_ID unusable as a KMS v2 KeyId", "ckaIDBytes", len(keyID), "error", err)
		return err
	}
	p.kekCkaID = keyID
	return nil
}

// SetKekKeyIDString sets the internal CKA_ID from a hex-encoded string.
func (p *P11) SetKekKeyIDString(hexKeyID string) error {
	if err := validateHexKeyID(hexKeyID); err != nil {
		slog.Error("SetKekKeyIDString: invalid hex key ID", "error", err)
		return err
	}
	kid, err := hex.DecodeString(hexKeyID)
	if err != nil {
		slog.Error("SetKekKeyIDString: failed to decode hex key ID", "error", err)
		return fmt.Errorf("invalid hex KeyID: %w", err)
	}
	p.kekCkaID = kid
	return nil
}

// GetKekKeyIDString returns the Key Encryption Key (KEK)  identifier as a
// hex-encoded string. This identifier is used to uniquely identify the
// encryption key within the PKCS#11 CKA_ID context.
func (p *P11) GetKekKeyIDString() string {
	return hex.EncodeToString(p.kekCkaID)
}

// GetKekCkaLabelByteA returns the KEK's CKA_LABEL as a UTF-8 encoded byte slice.
func (p *P11) GetKekCkaLabelByteA() []byte {
	return []byte(p.kekCkaLabel)
}

// SetHmacKeyIDString sets the internal HMAC Key ID from a hex-encoded string.
func (p *P11) SetHmacKeyIDString(hexHmacKeyID string) error {
	if err := validateHexKeyID(hexHmacKeyID); err != nil {
		slog.Error("SetHmacKeyIDString: invalid hex HMAC key ID", "error", err)
		return err
	}
	hmacID, err := hex.DecodeString(hexHmacKeyID)
	if err != nil {
		slog.Error("SetHmacKeyIDString: failed to decode hex HMAC key ID", "error", err)
		return fmt.Errorf("invalid hex HMAC KeyID: %w", err)
	}
	p.hmacCkaID = hmacID
	return nil
}

// GetHmacKeyIDString returns the HMAC Key ID as a hex-encoded string.
func (p *P11) GetHmacKeyIDString() string {
	return hex.EncodeToString(p.hmacCkaID)
}

// SetOldHmacKeyIDString sets the internal old HMAC Key ID from a hex-encoded string.
func (p *P11) SetOldHmacKeyIDString(hexOldHmacKeyID string) error {
	if err := validateHexKeyID(hexOldHmacKeyID); err != nil {
		slog.Error("SetOldHmacKeyIDString: invalid hex old HMAC key ID", "error", err)
		return err
	}
	oldHmacID, err := hex.DecodeString(hexOldHmacKeyID)
	if err != nil {
		slog.Error("SetOldHmacKeyIDString: failed to decode hex old HMAC key ID", "error", err)
		return fmt.Errorf("invalid hex HMAC KeyID: %w", err)
	}
	p.oldHmacCkaID = oldHmacID
	return nil
}

// SetOldKekKeyIDString sets the internal old KEK CKA_ID from a hex-encoded string.
func (p *P11) SetOldKekKeyIDString(hexOldKeyID string) error {
	if err := validateHexKeyID(hexOldKeyID); err != nil {
		slog.Error("SetOldKekKeyIDString: invalid hex old KEK key ID", "error", err)
		return err
	}
	kid, err := hex.DecodeString(hexOldKeyID)
	if err != nil {
		slog.Error("SetOldKekKeyIDString: failed to decode hex old KEK key ID", "error", err)
		return fmt.Errorf("invalid hex KeyID: %w", err)
	}
	p.oldKekCkaID = kid
	return nil
}

// SetEncryptor sets the gose.JWE Encryptor.
func (p *P11) SetEncryptor(encryptor gose.JweEncryptor) error {
	if encryptor == nil {
		return fmt.Errorf("SetEncryptor: encryptor is nil")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.encryptors == nil {
		p.encryptors = make(map[string]gose.JweEncryptor)
	}
	p.encryptors[p.GetKekKeyIDString()] = encryptor
	return nil
}

// SetEncryptors sets the map of encryptors.
func (p *P11) SetEncryptors(encryptors map[string]gose.JweEncryptor) error {
	if encryptors == nil {
		return fmt.Errorf("SetEncryptors: encryptors is nil")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.encryptors = encryptors
	return nil
}

// SetDecryptor sets the gose.JWE Decryptor.
func (p *P11) SetDecryptor(decryptor gose.JweDecryptor) error {
	if decryptor == nil {
		return fmt.Errorf("SetDecryptor: decryptor is nil")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.decryptors == nil {
		p.decryptors = make(map[string]gose.JweDecryptor)
	}
	p.decryptors[p.GetKekKeyIDString()] = decryptor
	return nil
}

// SetDecryptors sets the map of decryptors.
func (p *P11) SetDecryptors(decryptors map[string]gose.JweDecryptor) error {
	if decryptors == nil {
		return fmt.Errorf("SetDecryptors: decryptors is nil")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.decryptors = decryptors
	return nil
}

// SetContext sets the PKCS#11 context.
func (p *P11) SetContext(ctx *crypto11.Context) error {
	if ctx == nil {
		return fmt.Errorf("SetContext: ctx is nil")
	}
	p.ctx = ctx
	return nil
}

// Close the key manager
func (p *P11) Close() (err error) {
	p.mu.Lock()
	p.encryptors = nil
	p.decryptors = nil
	p.mu.Unlock()
	err = p.ctx.Close()

	return
}

// makeAeadKey creates a new AES-GCM AeadEncryptionKey from the given HSM key.
// kid is embedded in the JWE header and must match the label used at encrypt
// time; callers must pass the correct label (active or old KEK) explicitly.
func (p *P11) makeAeadKey(ctx *crypto11.Context, rng io.Reader, kek *crypto11.SecretKey, kid string) (aek gose.AeadEncryptionKey, err error) {
	var aead cipher.AEAD
	if aead, err = kek.NewGCM(); err != nil {
		return nil, fmt.Errorf("error while creating new gcm cipher: %w", err)
	}
	alg, err := aesGcmAlgFromKey(ctx, kek)
	if err != nil {
		return nil, fmt.Errorf("error detecting AES-GCM key size: %w", err)
	}
	if aek, err = gose.NewAesGcmCryptor(aead, rng, kid, alg, kekKeyOps); err != nil {
		return nil, fmt.Errorf("error while creating aead key: %w", err)
	}
	return
}

// aesGcmAlgFromKey queries the HSM key's CKA_VALUE_LEN attribute and maps the
// key length in bytes to the corresponding jose AES-GCM algorithm constant.
// An explicit ctx.GetAttribute call is required because the key size is not
// exposed through the crypto11.SecretKey interface.
func aesGcmAlgFromKey(ctx *crypto11.Context, key *crypto11.SecretKey) (jose.Alg, error) {
	attr, err := ctx.GetAttribute(key, crypto11.CkaValueLen)
	if err != nil {
		return "", fmt.Errorf("cannot read CKA_VALUE_LEN: %w", err)
	}
	var keyLenBytes uint64
	switch len(attr.Value) {
	case 4:
		keyLenBytes = uint64(binary.NativeEndian.Uint32(attr.Value))
	case 8:
		keyLenBytes = binary.NativeEndian.Uint64(attr.Value)
	default:
		return "", fmt.Errorf("unexpected CKA_VALUE_LEN size %d", len(attr.Value))
	}
	switch keyLenBytes {
	case 16:
		return jose.AlgA128GCM, nil
	case 24:
		return jose.AlgA192GCM, nil
	case 32:
		return jose.AlgA256GCM, nil
	default:
		return "", fmt.Errorf("unsupported AES key length %d bytes", keyLenBytes)
	}
}

// getIVFromDecryptRequest extracts the Initialization Vector from a KMS v2
// DecryptRequest. It first unmarshalls the JWE from the ciphertext, and
// then returns the InitializationVector from the unmarshalled JWE. If
// there is an error during unmarshalling, it is returned.
func getIVFromDecryptRequest(req *k8skmsv2.DecryptRequest) (iv []byte, err error) {
	var jwe jose.JweRfc7516Compact
	if err = jwe.Unmarshal(string(req.GetCiphertext())); err != nil {
		return nil, fmt.Errorf("error unmarshalling the jwe: %w", err)
	}
	if len(jwe.InitializationVector) == 0 {
		return nil, fmt.Errorf("no initialization vector found in jwe")
	}
	return jwe.InitializationVector, nil
}

// Decrypt decrypts an EncryptedObject-wrapped ciphertext for a Kubernetes KMS v2 DecryptRequest.
// TODO with kms-provider v2 api, the decrypt request body changed as : https://github.com/kubernetes/kms/blob/cf5ec9691661916fb7911e4545ed38d518f0430e/apis/v2/api.pb.go#L133C1-L133C17
//
//	  the protobuf of the k8s-kms-plugin should be changed according to the new version of the api
//	  -
//	  // The data to be decrypted.
//		 Ciphertext []byte
//		 // UID is a unique identifier for the request.
//	  // NOT	SURE IF IT IS NECESSARY FOR US
//		 Uid string
//		 // The keyID that was provided to the apiserver during encryption.
//		 // This represents the KMS KEK that was used to encrypt the data.
//		 KeyId string
//		 // Additional metadata that was sent by the KMS plugin during encryption.
//	  // NOT	SURE IF IT IS NECESSARY FOR US
//		 Annotations          map[string][]byte
func (p *P11) Decrypt(_ context.Context, req *k8skmsv2.DecryptRequest) (resp *k8skmsv2.DecryptResponse, err error) {
	var out []byte // buffer for the DecryptResponse.Plaintext
	var isRotation bool

	// Support key rotation
	switch req.KeyId {
	case p.GetKekKeyIDString():
		isRotation = false
	case hex.EncodeToString(p.oldKekCkaID):
		isRotation = true
	default:
		slog.Error("Decrypt: unknown key ID", "key_id", req.GetKeyId())
		return nil, fmt.Errorf("Decrypt: unknown key ID: %s", req.GetKeyId())
	}

	// decrypt with PKCS#11 context
	out, err = p.decryptWithContext(req, isRotation)
	if err != nil {
		slog.Error("error while decrypting with old key", "error", err)
		return nil, err
	}

	resp = &k8skmsv2.DecryptResponse{
		Plaintext: out,
	}
	return
}

// decryptWithContext performs decryption using the provided PKCS#11 context, DecryptRequest and decryptor map.
//
// The method takes into account if the key has been rotated and decrypts the
// ciphertext accordingly.
func (p *P11) decryptWithContext(req *k8skmsv2.DecryptRequest, isRotation bool) ([]byte, error) {
	var actualCtx *crypto11.Context
	var actualDecryptors map[string]gose.JweDecryptor
	var actualAlgo jose.Alg
	var actualKekCkaLabel string
	var actualHmacCkaID []byte
	var actualHmacCkaLabel string

	var decryptor gose.JweDecryptor // buffer
	var out []byte                  // buffer for the DecryptResponse.Plaintext
	var aad []byte                  // Additional Authenticated Data optional input used in authenticated encryption algorithms like AES-GCM or AES-CBC-HMAC
	var err error

	p.mu.RLock()
	if isRotation {
		actualCtx = p.oldCtx
		actualDecryptors = p.oldDecryptors
		actualAlgo = p.oldAlgorithmFamily
		actualKekCkaLabel = p.oldKekCkaLabel
		actualHmacCkaID = p.oldHmacCkaID
		actualHmacCkaLabel = p.oldHmacCkaLabel
	} else {
		actualCtx = p.ctx
		actualDecryptors = p.decryptors
		actualAlgo = p.algorithmFamily
		actualKekCkaLabel = p.kekCkaLabel
		actualHmacCkaID = p.hmacCkaID
		actualHmacCkaLabel = p.hmacCkaLabel
	}
	p.mu.RUnlock()

	// ML-KEM uses a binary envelope instead of JWE — handle it before the JWE decryptor path.
	if actualAlgo == AlgMLKEM {
		return p.decryptMLKEMWithContext(req, actualCtx)
	}

	p.mu.RLock()
	decryptor = actualDecryptors[req.GetKeyId()]
	p.mu.RUnlock()
	if decryptor == nil {
		if err = validateHexKeyID(req.GetKeyId()); err != nil {
			slog.Error("decryptWithContext: invalid key ID in DecryptRequest", "key_id", req.GetKeyId(), "error", err)
			return nil, fmt.Errorf("decryptWithContext: invalid key ID: %w", err)
		}

		// Random source from the HSM (pkcs11 context)
		var rng io.Reader
		if rng, err = actualCtx.NewRandomReader(); err != nil {
			slog.Error("error while creating random reader", "error", err)
			return nil, err
		}

		// convert the string DecryptRequest.KeyId containing a hex representation as string to hex []byte
		var reqKekKeyIDByteA []byte
		if reqKekKeyIDByteA, err = hex.DecodeString(req.GetKeyId()); err != nil {
			slog.Error("error while decoding the key id", "DecryptRequest.KeyId", req.GetKeyId(), "error", err)
			return nil, fmt.Errorf("error while decoding the key id: %w", err)
		}

		switch actualAlgo {
		case AlgAESGCM:
			slog.Log(context.Background(), logging.LevelTrace, "p11:Decrypt case", "algorithm", actualAlgo)

			// get kek by CKA_ID
			var kek *crypto11.SecretKey

			// Since the DecryptRequest comes from kubernetes, the only information k8s has is the keyId via the StatusResponse
			if kek, err = actualCtx.FindKey(reqKekKeyIDByteA, nil); nil != err {
				slog.Error("error while finding key by CKA_ID", "DecryptRequest.KeyId", req.GetKeyId(), "error", err)
				return nil, err
			}

			var aek gose.AeadEncryptionKey
			if aek, err = p.makeAeadKey(actualCtx, rng, kek, actualKekCkaLabel); err != nil {
				slog.Error("error while creating aead key", "error", err)
				return nil, err
			}
			decryptor = gose.NewJweDirectDecryptorAeadImpl([]gose.AeadEncryptionKey{aek})

			if out, aad, err = decryptor.Decrypt(string(req.GetCiphertext())); err != nil {
				slog.Error("error during decryption", "error", err)
				return nil, err
			}
			if nil != aad {
				// AAD should be nil - if not, needs to be changed in tandem with /Encrypt
				err = fmt.Errorf("bad AAD")
				slog.Error("error during decryption AAD should be nil", "error", err)
				return nil, err
			}
		case AlgAESCBC:
			slog.Log(context.Background(), logging.LevelTrace, "p11:Decrypt case", "algorithm", AlgAESCBC)
			// get kek by id
			var kek *crypto11.SecretKey
			if kek, err = actualCtx.FindKey(reqKekKeyIDByteA, nil); nil != err {
				slog.Error("error finding key by ID", "error", err)
				return nil, err
			}

			// for decryption, we have to retrieve the iv from the jwe
			var iv []byte
			if iv, err = getIVFromDecryptRequest(req); err != nil {
				return nil, err
			}
			// Initialize the CBC key for decryption
			var blockMode crypto11.BlockModeCloser
			if blockMode, err = kek.NewCBCDecrypterCloser(iv); err != nil {
				return nil, fmt.Errorf("error initializing block cipher: %w", err)
			}

			cbcKey := gose.NewAesCbcCryptor(blockMode, req.GetKeyId(), jose.AlgA256CBC)
			// Initialize the hmac key for authentication
			var hmacp11Key *crypto11.SecretKey
			if hmacp11Key, err = actualCtx.FindKey(actualHmacCkaID, []byte(actualHmacCkaLabel)); err != nil {
				return nil, fmt.Errorf("error getting hmac key from HSM with label '%s' or id '%s': %w", actualHmacCkaLabel, actualHmacCkaID, err)
			}
			var hash hash.Hash
			if hash, err = hmacp11Key.NewHMAC(pkcs11.CKM_SHA256_HMAC, 0); err != nil {
				return nil, fmt.Errorf("error initializing SHA26 with key '%s': %w", actualHmacCkaLabel, err)
			}
			hmacKey := gose.NewHmacShaCryptor(actualHmacCkaLabel, hash)
			// decryptor
			decryptor = gose.NewJweDirectDecryptorBlock(cbcKey, hmacKey)
			// !!! It is very important to finalize each PKCS11 operation
			defer blockMode.Close()

			if out, aad, err = decryptor.Decrypt(string(req.GetCiphertext())); err != nil {
				slog.Error("error during decryption", "error", err)
				return nil, err
			}
			if nil != aad {
				// AAD should be nil - if not, needs to be changed in tandem with /Encrypt
				err = fmt.Errorf("bad AAD")
				slog.Error("error during decryption AAD should be nil", "error", err)
				return nil, err
			}
		case AlgRSAOAEP:
			slog.Log(context.Background(), logging.LevelTrace, "p11:Decrypt case", "algorithm", AlgRSAOAEP)
			// load pkcs11 context
			var rsaKeyPair crypto11.SignerDecrypter
			if rsaKeyPair, err = actualCtx.FindRSAKeyPair(reqKekKeyIDByteA, nil); err != nil {
				slog.Error("error finding RSA key pair", "keyId", fmt.Sprintf("%X", reqKekKeyIDByteA), "error", err)
				return nil, fmt.Errorf("error finding RSA key pair with id %X: %w", reqKekKeyIDByteA, err)
			}

			var privKey *hsm.AsymmetricDecryptionKey
			if privKey, err = hsm.NewAsymmetricDecryptionKey(p.ctx, rsaKeyPair, reqKekKeyIDByteA, nil); err != nil {
				slog.Error("error creating AsymmetricDecryptionKey", "keyId", fmt.Sprintf("%X", reqKekKeyIDByteA), "error", err)
				return nil, fmt.Errorf("error creating AsymmetricDecryptionKey with id %X: %w", reqKekKeyIDByteA, err)
			}
			// create key store from private key
			var store gose.AsymmetricDecryptionKeyStore
			if store, err = gose.NewAsymmetricDecryptionKeyStoreImpl(map[string]gose.AsymmetricDecryptionKey{req.GetKeyId(): privKey}); err != nil {
				slog.Error("error creating AsymmetricDecryptionKeyStore", "keyId", fmt.Sprintf("%X", reqKekKeyIDByteA), "error", err)
				return nil, fmt.Errorf("error creating AsymmetricDecryptionKeyStore with id %X: %w", reqKekKeyIDByteA, err)
			}

			// create decryptor
			decryptor := gose.NewJweRsaKeyEncryptionDecryptorImpl(store)

			// Decrypt with an explicit SHA-256 rather than crypto.Hash(0) (which would derive the
			// digest from the "alg" header). This plugin has only ever wrapped the CEK with
			// SHA-256, so SHA-256 is correct for every object it can encounter — including those
			// written before gose v1.0.0-rc2, whose headers say "RSA-OAEP" (SHA-1 per RFC 7518)
			// while the CEK is SHA-256-wrapped. Deriving from the header would fail on exactly
			// those, and a KMS plugin must never lose the ability to read its own data at rest.
			out, _, err = decryptor.Decrypt(string(req.GetCiphertext()), crypto.SHA256)
			if err != nil {
				slog.Error("decryption failed", "error", err)
				return nil, err
			}
		default:
			slog.Error("Decrypt: algorithm not supported")
		}
	}
	return out, nil
}

// Encrypt encrypts plaintext for a Kubernetes KMS v2 EncryptRequest using the configured KEK algorithm family.
// TODO support RSA encryption
//   - load the public key from the KMS and encrypt the cyphertext using gose encryptor
//   - For the EncryptResponse in https://github.com/kubernetes/kms/blob/cf5ec9691661916fb7911e4545ed38d518f0430e/apis/v2/api.pb.go#L287:
//   - use the 'Ciphertext' attribute for with the encrypted ciphertext only (ciphertext of jwe)
//   - Use the 'KeyID' attribute with the TPM's key ID for decryption
//   - Use the 'Annotations' attribute for additional information like the nonce
//     ..
//     with kms-provider v2 api, the encryp request body changed as : https://github.com/kubernetes/kms/blob/cf5ec9691661916fb7911e4545ed38d518f0430e/apis/v2/api.pb.go#L133C1-L133C17
//     the protobuf of the k8s-kms-plugin should be changed according to the new version of the api
//     -
//     // The data to be encrypted.
//     Plaintext []byte `protobuf:"bytes,1,opt,name=plaintext,proto3" json:"plaintext,omitempty"`
//     // UID is a unique identifier for the request.
//     // NOT	SURE IF IT IS NECESSARY FOR US
//     Uid string
func (p *P11) Encrypt(ctx context.Context, req *k8skmsv2.EncryptRequest) (resp *k8skmsv2.EncryptResponse, err error) {
	// ML-KEM uses a binary envelope instead of JWE — handle it before the JWE encryptor path.
	if p.algorithmFamily == AlgMLKEM {
		return p.encryptMLKEM(ctx, req)
	}

	var encryptor gose.JweEncryptor
	var out string // buffer for the EncryptResponse.Ciphertext

	// p.kid is initialized by NewP11
	p.mu.RLock()
	encryptor = p.encryptors[p.GetKekKeyIDString()]
	p.mu.RUnlock()
	if encryptor == nil {
		// Select algorithm
		switch p.algorithmFamily {
		case AlgAESGCM:
			slog.Log(ctx, logging.LevelTrace, "p11:Encrypt case", "algorithm", p.algorithmFamily)
			// Find the KEK in the KMS
			var kek *crypto11.SecretKey
			if kek, err = p.ctx.FindKey(p.kekCkaID, p.GetKekCkaLabelByteA()); nil != err {
				slog.Error("Encrypt: cannot find a symmetric key", "algorithm", p.algorithmFamily, "label", p.kekCkaLabel, "keyId", p.GetKekKeyIDString(), "error", err)
				return
			}

			// Random source from the HSM (pkcs11 context)
			var rng io.Reader
			if rng, err = p.ctx.NewRandomReader(); err != nil {
				slog.Error("Encrypt: cannot get a random source from the HSM (pkcs11 context)", "error", err)
				return
			}
			var aek gose.AeadEncryptionKey
			if aek, err = p.makeAeadKey(p.ctx, rng, kek, p.kekCkaLabel); err != nil {
				slog.Error("Encrypt: cannot create an aead key", "error", err)
				return
			}

			encryptor = gose.NewJweDirectEncryptorAead(aek, p.config.UseGCMIVFromHSM)
			// output is the marshalled jwe
			if out, err = encryptor.Encrypt(req.GetPlaintext(), nil); err != nil {
				slog.Error("Encrypt: encryption failed", "error", err)
				return
			}

		case AlgAESCBC:
			slog.Log(ctx, logging.LevelTrace, "p11:Encrypt case", "algorithm", AlgAESCBC)
			// Find the KEK in the KMS
			var kek *crypto11.SecretKey
			if kek, err = p.ctx.FindKey(p.kekCkaID, p.GetKekCkaLabelByteA()); nil != err {
				slog.Error("Encrypt: cannot find a symmetric key", "algorithm", p.algorithmFamily, "label", p.kekCkaLabel, "keyId", p.GetKekKeyIDString(), "error", err)
				return
			}

			// Random source from the HSM (pkcs11 context)
			var rng io.Reader
			if rng, err = p.ctx.NewRandomReader(); err != nil {
				slog.Error("Encrypt: cannot get a random source from the HSM (pkcs11 context)", "error", err)
				return
			}
			// generate the IV from the KMS, using the kek block size
			iv := make([]byte, kek.Cipher.BlockSize)
			if _, err = rng.Read(iv); err != nil {
				return
			}
			// Initialize the CBC key for encryption
			var blockMode crypto11.BlockModeCloser
			if blockMode, err = kek.NewCBCEncrypterCloser(iv); err != nil {
				return nil, fmt.Errorf("error initializing block cipher: %w", err)
			}
			// jose.AlgA256CBC is the only standardized JWE AES-CBC key size (unlike AES-GCM
			// which exists as AlgA128GCM / AlgA192GCM / AlgA256GCM). The key on the HSM must be 256-bit.
			cbcKey := gose.NewAesCbcCryptor(blockMode, p.GetKekKeyIDString(), jose.AlgA256CBC)

			// Initialize the hmac key for authentication TODO: consider allowing user to use a CKA_ID to get the HMAC key
			var hmacp11Key *crypto11.SecretKey
			if hmacp11Key, err = p.ctx.FindKey(p.hmacCkaID, []byte(p.hmacCkaLabel)); err != nil {
				return nil, fmt.Errorf("error getting hmac key from HSM with label '%s' and id '%s': %w", p.hmacCkaLabel, p.GetHmacKeyIDString(), err)
			}
			var hash hash.Hash
			if hash, err = hmacp11Key.NewHMAC(pkcs11.CKM_SHA256_HMAC, 0); err != nil {
				return nil, fmt.Errorf("error initializing CKM_SHA256_HMAC with key '%s': %w", p.hmacCkaLabel, err)
			}
			hmacKey := gose.NewHmacShaCryptor(p.hmacCkaLabel, hash)
			// encryptor
			encryptor = gose.NewJweDirectEncryptorBlock(cbcKey, hmacKey, iv)
			// !!! It is very important to finalize each PKCS11 operation
			defer blockMode.Close()
			// output is the marshalled jwe
			if out, err = encryptor.Encrypt(req.GetPlaintext(), nil); err != nil {
				slog.Error("Encrypt: encryption failed", "error", err)
				return
			}

		case AlgRSAOAEP:
			slog.Log(ctx, logging.LevelTrace, "p11:Encrypt case", "algorithm", AlgRSAOAEP)
			//TODO generate a jwk with the kid of the public key. Ex :
			//      {"kty":"EC",
			//         "crv":"P-256",
			//         "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
			//         "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
			//         "use":"enc",
			//         "kid":"1"},
			//        {"kty":"RSA",
			//         "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx
			//    4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs
			//    tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2
			//    QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI
			//    SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb
			//    w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
			//         "e":"AQAB",
			//         "alg":"RS256",
			//         "kid":"2011-04-29"
			//    }
			var rsaKeyPair crypto11.SignerDecrypter
			if rsaKeyPair, err = p.ctx.FindRSAKeyPair(p.kekCkaID, p.GetKekCkaLabelByteA()); err != nil {
				slog.Error("Encrypt: cannot find an rsa key pair", "algorithm", p.algorithmFamily, "label", p.kekCkaLabel, "keyId", p.GetKekKeyIDString(), "error", err)
				return nil, err
			}

			// ENCRYPTION
			// get public key
			pubkey := rsaKeyPair.Public()

			// generate jwk from public key
			var pubJwk jose.Jwk
			if pubJwk, err = gose.JwkFromPublicKey(pubkey, []jose.KeyOps{jose.KeyOpsEncrypt}, nil); err != nil {
				slog.Error("Failed to create JWE RSA Key Encryption Encryptor", "error", err)
				return nil, err
			}
			// set JWK Algorithm for encryption
			pubJwk.SetAlg(jose.AlgRSAOAEP)

			// encrypt plaintext
			var rsaEncryptor *gose.JweRsaKeyEncryptionEncryptorImpl
			if rsaEncryptor, err = gose.NewJweRsaKeyEncryptionEncryptorImpl(pubJwk, rand.Reader); err != nil {
				slog.Error("Failed to create JWE RSA Key Encryption Encryptor", "error", err)
				return nil, err
			}
			// output is the marshalled jwe
			if out, err = rsaEncryptor.Encrypt(req.GetPlaintext(), crypto.SHA256); err != nil {
				slog.Error("Encrypt: encryption failed", "error", err)
				return
			}
		default:
			slog.Error("Encrypt: unsupported algorithm", "algorithm", p.algorithmFamily)
		}
	}

	if err = validateEncryptResponseCiphertext([]byte(out)); err != nil {
		slog.Error("Encrypt: refusing to return a ciphertext the API server would reject",
			"algorithm", p.algorithmFamily, "ciphertextLen", len(out), "kekCkaLabelLen", len(p.kekCkaLabel),
			"kekCkaIDHexLen", len(p.GetKekKeyIDString()), "error", err,
			"action", "shorten the KEK CKA_LABEL or CKA_ID: both are carried in the JWE header and inflate every ciphertext")
		return nil, fmt.Errorf("Encrypt: %w", err)
	}

	resp = &k8skmsv2.EncryptResponse{
		// the bytes array contains the bytes of the marshalled jwe
		Ciphertext: []byte(out),
		KeyId:      p.GetKekKeyIDString(),
	}
	putAlgorithmFamily(resp, p.algorithmFamily)
	if err = validateEncryptResponseAnnotations(resp.Annotations); err != nil {
		slog.Error("Encrypt: refusing to return annotations the API server would reject",
			"algorithm", p.algorithmFamily, "annotationSizes", annotationSizes(resp.Annotations), "error", err)
		return nil, fmt.Errorf("Encrypt: %w", err)
	}
	slog.Log(ctx, logging.LevelTrace, "Encrypt: returning response", "algorithm", p.algorithmFamily, "ciphertextLen", len(resp.Ciphertext), "annotationSizes", annotationSizes(resp.Annotations))
	return resp, nil
}

// annotationSizes maps an EncryptResponse.Annotations map to key -> byte length, for logging.
func annotationSizes(annotations map[string][]byte) map[string]int {
	sizes := make(map[string]int, len(annotations))
	for k, v := range annotations {
		sizes[k] = len(v)
	}
	return sizes
}

// UnaryInterceptor is a gRPC unary server interceptor that logs each KMS v2 RPC.
func (p *P11) UnaryInterceptor(ctx context.Context, req interface{}, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
	switch req.(type) {
	case *k8skmsv2.StatusRequest:
		{
			slog.Log(ctx, logging.LevelTrace, "UnaryInterceptor kms v2 StatusRequest")
		}
	case *k8skmsv2.EncryptRequest:
		{
			slog.Log(ctx, logging.LevelTrace, "UnaryInterceptor kms v2 EncryptRequest")
			pt := (req).(*k8skmsv2.EncryptRequest).GetPlaintext()
			if len(pt) == 0 {
				slog.Error("UnaryInterceptor: plaintext is empty in EncryptRequest")
				return nil, status.Errorf(codes.InvalidArgument, "UnaryInterceptor: plaintext is empty")
			}
			if len(pt) > maxPlaintextSize {
				slog.Error("UnaryInterceptor: plaintext exceeds maximum size", "size", len(pt), "max", maxPlaintextSize)
				return nil, status.Errorf(codes.InvalidArgument, "UnaryInterceptor: plaintext size %d exceeds maximum of %d bytes", len(pt), maxPlaintextSize)
			}
		}
	case *k8skmsv2.DecryptRequest:
		{
			slog.Log(ctx, logging.LevelTrace, "UnaryInterceptor kms v2 DecryptRequest")
			decReq := (req).(*k8skmsv2.DecryptRequest)
			if decReq.GetKeyId() == "" {
				slog.Error("UnaryInterceptor: KeyId is empty in the DecryptRequest")
				return nil, status.Errorf(codes.InvalidArgument, "UnaryInterceptor: KeyId is empty in the DecryptRequest")
			}
			if len(decReq.GetCiphertext()) == 0 {
				slog.Error("UnaryInterceptor: ciphertext is empty in DecryptRequest")
				return nil, status.Errorf(codes.InvalidArgument, "UnaryInterceptor: ciphertext is empty")
			}
			if len(decReq.GetCiphertext()) > maxKMSv2CiphertextSize {
				slog.Error("UnaryInterceptor: ciphertext exceeds maximum size", "size", len(decReq.GetCiphertext()), "max", maxKMSv2CiphertextSize)
				return nil, status.Errorf(codes.InvalidArgument, "UnaryInterceptor: ciphertext size %d exceeds maximum of %d bytes", len(decReq.GetCiphertext()), maxKMSv2CiphertextSize)
			}
		}
	default:
		{
			slog.Log(ctx, logging.LevelTrace, "UnaryInterceptor default")
		}
	}

	resp, err = handler(ctx, req)
	if err != nil {
		slog.Error("error", "error", err)
	}
	return resp, err
}

// Status returns the StatusResponse for the KMS plugin. There are two cases:
// The returned StatusResponse contains the KeyID of the KEK (CKA_ID), the Healthz and the Version.
//
// Status() method comes from the KeyManagementServiceClient interface from "k8s.io/kms/apis/v2"
// See https://pkg.go.dev/k8s.io/kms/apis/v2#KeyManagementServiceClient
// Also check the content of a StatusResponse
// See https://pkg.go.dev/k8s.io/kms/apis/v2#StatusResponse
func (p *P11) Status(ctx context.Context, _ *k8skmsv2.StatusRequest) (statusResponse *k8skmsv2.StatusResponse, err error) {
	slog.Log(ctx, logging.LevelTrace, "p11 Status: entering method")

	// NewP11 should populate both KEK ID (CKA_ID) and Key label (CKA_LABEL), but check the content just in case.
	if p.kekCkaID == nil {
		err = errors.New("KEK ID is nil")
		slog.Error("p11 Status: error due to missing KEK ID", "error", err)
		return
	}

	if len(p.kekCkaID) == 0 {
		err = errors.New("KEK ID is empty")
		slog.Error("p11 Status: error due to missing KEK ID", "error", err)
		return
	}

	statusResponse = &k8skmsv2.StatusResponse{
		Version: "v2",
		Healthz: "ok",
		KeyId:   p.GetKekKeyIDString(),
	}

	slog.Log(ctx, logging.LevelTrace, "StatusResponse", "Version", statusResponse.Version, "Healthz", statusResponse.Healthz, "KeyId", statusResponse.KeyId)
	return statusResponse, nil
}

// FindCkaAttrByIDOrLabel find a CKA attribute like CKA_ID or CKA_LABEL by id or by label.
func FindCkaAttrByIDOrLabel(ctx *crypto11.Context, algorithm jose.Alg, ckaAttr crypto11.AttributeType, id, label []byte) ([]byte, error) {
	var outBuf []byte // output buffers

	if ( // find ID by label
	(len(id) == 0) &&
		(label != nil || len(label) > 0) &&
		(ckaAttr == crypto11.CkaId)) ||
		( // find label by ID
		(id != nil || len(id) > 0) &&
			(len(label) == 0) &&
			(ckaAttr == crypto11.CkaLabel)) {

		var err error
		switch algorithm {
		case AlgAESGCM, AlgAESCBC:
			// Find the key in the KMS for AES symmetric algorithms
			var symKey *crypto11.SecretKey
			if symKey, err = ctx.FindKey(id, label); nil != err {
				slog.Error("FindCkaAttrByIDOrLabel: cannot find a symmetric key", "algorithm", algorithm, "label", fmt.Sprintf("%x", label), "id", fmt.Sprintf("%x", id), "error", err)
				return nil, err
			}

			// Get the CKA_ID to obtain the KEK key id
			var attr *crypto11.Attribute
			if attr, err = ctx.GetAttribute(symKey, ckaAttr); err != nil {
				slog.Error("FindCkaAttrByIDOrLabel: cannot get the CKA_ attribute", "ckaAttr", ckaAttr, "algorithm", algorithm, "label", fmt.Sprintf("%x", label), "id", fmt.Sprintf("%x", id), "error", err)
				return nil, err
			}
			outBuf = attr.Value
		case AlgRSAOAEP:
			// Find the key in the KMS for RSA asymmetric algorithms
			var rsaKeyPair crypto11.SignerDecrypter
			if rsaKeyPair, err = ctx.FindRSAKeyPair(id, label); err != nil {
				slog.Error("FindCkaAttrByIDOrLabel: cannot find an rsa key pair", "label", fmt.Sprintf("%x", label), "id", fmt.Sprintf("%x", id), "error", err)
				return nil, err
			}

			// Get the key id by key label
			var attr *crypto11.Attribute
			if attr, err = ctx.GetAttribute(rsaKeyPair, ckaAttr); err != nil {
				slog.Error("FindCkaAttrByIDOrLabel: cannot get the CKA_ attribute", "ckaAttr", ckaAttr, "algorithm", algorithm, "label", fmt.Sprintf("%x", label), "id", fmt.Sprintf("%x", id), "error", err)
				return nil, err
			}
			outBuf = attr.Value
		case AlgMLKEM:
			// Find the ML-KEM key pair on the HSM
			var mlkemKP crypto11.MLKEMKeyPair
			if mlkemKP, err = ctx.FindMLKEMKeyPair(id, label); err != nil {
				slog.Error("FindCkaAttrByIDOrLabel: cannot find ML-KEM key pair", "label", fmt.Sprintf("%x", label), "id", fmt.Sprintf("%x", id), "error", err)
				return nil, err
			}
			var attr *crypto11.Attribute
			if attr, err = ctx.GetAttribute(mlkemKP, ckaAttr); err != nil {
				slog.Error("FindCkaAttrByIDOrLabel: cannot get CKA_ attribute for ML-KEM key", "ckaAttr", ckaAttr, "label", fmt.Sprintf("%x", label), "id", fmt.Sprintf("%x", id), "error", err)
				return nil, err
			}
			outBuf = attr.Value
		}
	} else {
		slog.Error("FindCkaAttrByIDOrLabel: cannot find a key with parameters", "id", fmt.Sprintf("%x", id), "label", fmt.Sprintf("%x", label))
		return nil, fmt.Errorf("FindCkaAttrByIDOrLabel: cannot find a key with parameters id%x and label%x", id, label)
	}

	return outBuf, nil
}

// GetKeyIDAndLabel checks the CKA_ID and CKA_LABEL of a key from the P11 provider, and returns
// both of the value from one or the other.
// Indeed, Key ID and Key Label are mutually exclusive and at least one must be provided.
// If the Key ID is provided only, this function retrieves the label of the key.
// If the Key Label is provided, this function retrieves the ID of the key.
// If the key Label is provided and the key is retrieved without a Key ID from the HSM, the process
// exits with a fatal error. Indeed, the K8S KMS v2 protocol requires a Key ID (CKA_ID) for status
// requests.
func GetKeyIDAndLabel(p *P11, keyID string, keyLabel string) (resultKeyID []byte, resultKeyLabel string, err error) {
	var resultKeyLabelBytes []byte
	if keyID == "" && keyLabel != "" {
		if err = validateCkaLabel(keyLabel); err != nil {
			slog.Error("GetKeyIDAndLabel: invalid CKA_LABEL", "error", err)
			return nil, "", err
		}
		slog.Log(context.Background(), logging.LevelTrace, "NewP11: key id (CKA_ID) is empty. Find CKA_ID by CKA_LABEL", "label", keyLabel)
		resultKeyLabel = keyLabel

		keyLabelBytes := []byte(keyLabel)
		resultKeyID, err = FindCkaAttrByIDOrLabel(p.ctx, p.algorithmFamily, crypto11.CkaId, nil, keyLabelBytes)
		if err != nil {
			slog.Error("no key found in HSM with the given CKA_LABEL — verify the label matches a key present on the configured PKCS#11 token",
				"label", resultKeyLabel, "error", err)
			return nil, "", err
		}

		if len(resultKeyID) == 0 {
			logging.Fatal("key found by CKA_LABEL has no CKA_ID set",
				"label", keyLabel,
				"reason", "CKA_ID is used as the KEK ID stored in Kubernetes etcd; it must be stable and unambiguous to guarantee secret recoverability",
				"action", "set a CKA_ID on this key using your HSM management tool (e.g. pkcs11-tool --id <hex-id>) before starting the plugin")
		}

		// The CKA_ID came from the token, not from validateHexKeyID, so it is not yet known to
		// fit the KMS v2 KeyId bound.
		if err = validateKMSv2KeyID(hex.EncodeToString(resultKeyID)); err != nil {
			slog.Error("CKA_ID found by CKA_LABEL is unusable as a KMS v2 KeyId",
				"label", keyLabel, "ckaIDBytes", len(resultKeyID), "error", err,
				"action", "provision this key with a shorter CKA_ID (at most 512 bytes) using your HSM management tool")
			return nil, "", fmt.Errorf("GetKeyIDAndLabel: CKA_ID found by CKA_LABEL %q: %w", keyLabel, err)
		}
	} else if keyID != "" && keyLabel == "" {
		// Case: KEK ID already provided by user at startup with flag --p11-key-id
		// If k8sKekLabel is empty but kekkeyid is not nil, we can get the key label by the key id. But
		// the only purpose of this is for logging messages, as the CKA_LABEL is not use in the KMS v2
		// API calls.
		// But we could use EncryptResponse.Annotations and DecryptRequest.Annotations to store
		// the value of the key label CKA_LABEL.
		slog.Log(context.Background(), logging.LevelTrace, "NewP11: key label (CKA_LABEL) is empty but key id (CKA_ID) is not empty. Find CKA_LABEL by CKA_ID", "keyId", keyID)
		if err = validateHexKeyID(keyID); err != nil {
			slog.Error("GetKeyIDAndLabel: invalid hex key ID format", "error", err)
			return nil, "", fmt.Errorf("GetKeyIDAndLabel: invalid hex key ID: %w", err)
		}
		resultKeyID, err = hex.DecodeString(keyID)
		if err != nil {
			return nil, "", fmt.Errorf("NewP11: cannot decode string CKA_ID into hex expected format '%s': %w", keyID, err)
		}

		if resultKeyLabelBytes, err = FindCkaAttrByIDOrLabel(p.ctx, p.algorithmFamily, crypto11.CkaLabel, resultKeyID, nil); err != nil {
			slog.Error("NewP11: failed to find key CKA_LABEL by CKA_ID", "keyId", fmt.Sprintf("%x", resultKeyID), "error", err)
			return nil, "", err
		}
		resultKeyLabel = string(resultKeyLabelBytes)
	} else if keyID == "" && keyLabel == "" {
		const errMsg = "NewP11: key ID (CKA_ID) and key label (CKA_LABEL) are both empty, please provide one of them"
		slog.Error(errMsg)
		return nil, "", errors.New(errMsg)
	} else {
		const errMsg = "NewP11: both key ID (CKA_ID) and key label (CKA_LABEL) are provided, please provide only one"
		slog.Error(errMsg)
		return nil, "", errors.New(errMsg)
	}

	return
}
