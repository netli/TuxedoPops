/*
Copyright (c) 2016 Skuchain,Inc

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

package ElementProof

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec"
	"github.com/golang/protobuf/proto"
	"github.com/skuchain/kevlar/ProofElementStore"
)

type SecP256k1ElementProof struct {
	ProofName    string
	State        SigState
	Signatures   []btcec.Signature
	PublicKeys   []btcec.PublicKey
	SupercededBy string
	Threshold    int
	Data         string
}

//PubKeys hello
func (b *SecP256k1ElementProof) PubKeys() []string {
	output := *new([]string)
	for _, key := range b.PublicKeys {
		output = append(output, hex.EncodeToString(key.SerializeCompressed()))
	}
	return output
}

func (b *SecP256k1ElementProof) CurrentState() SigState {
	return b.State
}

func (b *SecP256k1ElementProof) Name() string {
	return b.ProofName
}

func (b *SecP256k1ElementProof) verifySigs(message string, signatures *[][]byte) (bool, []btcec.Signature) {
	validSig := false
	validatedSigs := *new([]btcec.Signature)
	usedKeys := make([]bool, len(b.PublicKeys))
	messageBytes := sha256.Sum256([]byte(message))
	for _, sigbytes := range *signatures {

		signature, err := btcec.ParseDERSignature(sigbytes, btcec.S256())
		if err != nil {
			fmt.Println("Bad signature encoding")
			return false, nil
		}
		validSig = false

		for i, pubKey := range b.PublicKeys {
			success := signature.Verify(messageBytes[:], &pubKey)
			if success && (usedKeys[i] == false) {
				validSig = true
				validatedSigs = append(validatedSigs, *signature)
				usedKeys[i] = true
			}
		}
	}

	if validSig == false {
		return false, nil
	}
	if len(validatedSigs) < b.Threshold {
		return false, nil
	}
	return validSig, validatedSigs
}
func (b *SecP256k1ElementProof) Supercede(signatures *[][]byte, supercededBy string, supercedingName string) bool {

	success, sigs := b.verifySigs(b.ProofName+":superceded:"+supercededBy, signatures)
	if !success {
		return false
	}

	if b.State == Initialized || b.State == Signed || b.State == Revoked {
		b.State = Superceded
		b.SupercededBy = supercedingName
		b.Signatures = sigs
		return true
	}
	return false
}

func (b *SecP256k1ElementProof) Revoked(signatures *[][]byte) bool {

	success, sigs := b.verifySigs(b.ProofName+":revoked", signatures)
	if !success {
		return false
	}

	if b.State == Initialized || b.State == Signed {
		b.State = Revoked
		b.Signatures = sigs
		return true
	}
	return false
}

func (b *SecP256k1ElementProof) Signed(signatures *[][]byte, data string) bool {

	success, sigs := b.verifySigs(b.ProofName+":"+data, signatures)
	if !success {
		return false
	}
	if b.State == Initialized {
		b.State = Signed
		b.Signatures = sigs
		b.Data = data
		return true
	}
	return false
}

func (b *SecP256k1ElementProof) Fulfillment() string {

	return "Not Implemented Yet"
}

func (b *SecP256k1ElementProof) ToBytes() []byte {
	store := ProofElementStore.SECPProofElementStore{}
	store.Name = b.ProofName
	store.Data = b.Data
	store.SupercededBy = b.SupercededBy
	store.Threshold = int32(b.Threshold)
	switch b.State {
	case Initialized:
		store.State = ProofElementStore.SECPProofElementStore_Initialized
	case Signed:
		store.State = ProofElementStore.SECPProofElementStore_Signed
	case Revoked:
		store.State = ProofElementStore.SECPProofElementStore_Revoked
	case Superceded:
		store.State = ProofElementStore.SECPProofElementStore_Superceded
	}

	for _, key := range b.PublicKeys {
		store.PublicKeys = append(store.PublicKeys, key.SerializeCompressed())
	}
	for _, sigs := range b.Signatures {
		store.Signatures = append(store.Signatures, sigs.Serialize())
	}
	metastore := ProofElementStore.ProofElementStore{}
	metastore.Type = ProofElementStore.ProofElementStore_SECP
	metastore.Secp = &store

	bufferBytes, err := proto.Marshal(&metastore)
	if err != nil {
		fmt.Println(err)
	}
	return bufferBytes
}

func (b *SecP256k1ElementProof) FromBytes(bits []byte) error {
	metastore := ProofElementStore.ProofElementStore{}
	err := proto.Unmarshal(bits, &metastore)
	if err != nil {
		return err
	}
	if metastore.Type != ProofElementStore.ProofElementStore_SECP {
		return errors.New("Expected SECP proof")
	}
	store := metastore.Secp
	b.ProofName = store.Name
	b.Data = store.Data
	b.SupercededBy = store.SupercededBy
	b.Threshold = int(store.Threshold)
	switch store.State {
	case ProofElementStore.SECPProofElementStore_Initialized:
		b.State = Initialized
	case ProofElementStore.SECPProofElementStore_Signed:
		b.State = Signed
	case ProofElementStore.SECPProofElementStore_Revoked:
		b.State = Revoked
	case ProofElementStore.SECPProofElementStore_Superceded:
		b.State = Superceded
	}
	for _, key := range store.PublicKeys {
		publicKey, err := btcec.ParsePubKey(key, btcec.S256())
		if err != nil {
			return err
		}
		b.PublicKeys = append(b.PublicKeys, *publicKey)
	}
	for _, sig := range store.Signatures {
		signature, err := btcec.ParseSignature(sig, btcec.S256())
		if err != nil {
			return err
		}
		b.Signatures = append(b.Signatures, *signature)
	}
	return nil
}

func (b *SecP256k1ElementProof) ToJSON() []byte {
	type JSONBracket struct {
		ProofName    string
		State        string
		Signatures   []string
		PublicKeys   []string
		SupercededBy string
		Threshold    int
		Data         string
	}
	jsonBracket := JSONBracket{}

	jsonBracket.ProofName = b.ProofName
	switch b.State {
	case Initialized:
		jsonBracket.State = "Initialized"
	case Signed:
		jsonBracket.State = "Signed"
	case Revoked:
		jsonBracket.State = "Revoked"
	case Superceded:
		jsonBracket.State = "Superceded"
	}
	for _, sig := range b.Signatures {
		jsonBracket.Signatures = append(jsonBracket.Signatures, hex.EncodeToString(sig.Serialize()))
	}
	for _, pubKey := range b.PublicKeys {
		jsonBracket.PublicKeys = append(jsonBracket.PublicKeys, hex.EncodeToString(pubKey.SerializeCompressed()))
	}
	jsonBracket.SupercededBy = b.SupercededBy
	jsonBracket.Threshold = b.Threshold
	jsonBracket.Data = b.Data

	jsonstring, err := json.Marshal(jsonBracket)
	if err != nil {
		return nil
	}
	return jsonstring
}

func (b *SecP256k1ElementProof) VerifyIdentities(idKeys []btcec.PublicKey, uuid string) bool {
	hashedUUID := sha256.Sum256([]byte(uuid))
	doubleHashedUUID := sha256.Sum256(hashedUUID[:])
	encodedHash := hex.EncodeToString(doubleHashedUUID[:])
	if encodedHash != b.ProofName {
		return false
	}
	curve := btcec.S256()
	offsetX, offsetY := curve.ScalarBaseMult(hashedUUID[:])
	usedKeys := make([]bool, len(b.PublicKeys))
	countUsed := 0

	for _, idkey := range idKeys {
		offsettedX, offsettedY := curve.Add(idkey.X, idkey.Y, offsetX, offsetY)
		for i, key := range b.PublicKeys {
			if key.X == offsettedX && key.Y == offsettedY {
				usedKeys[i] = true
				countUsed++
			}
		}
	}
	if countUsed == len(b.PublicKeys) {
		return true
	}
	return false
}
