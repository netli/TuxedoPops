/*
Copyright (c) 2016 Skuchain,Inc

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

package OTX

import (
	"encoding/hex"
	"encoding/json"

	"github.com/btcsuite/btcd/btcec"
)

type SecP256k1Output struct {
	Owners    []btcec.PublicKey
	OutputIdx int
	Threshold int
	Data      string
	Amount    int
	Creator   btcec.PublicKey
}

func New(creator btcec.PublicKey, idx int, amount int, data string) SecP256k1Output {
	code := SecP256k1Output{}
	code.OutputIdx = idx
	code.Data = data
	code.Amount = amount
	code.Creator = creator

	return code
}

//PubKeys hello
func (b *SecP256k1Output) PubKeys() []string {
	output := *new([]string)
	for _, key := range b.Owners {
		output = append(output, hex.EncodeToString(key.SerializeCompressed()))
	}
	return output
}

// func (b *SecP256k1Output) verifySigs(message string, signatures *[][]byte) (bool, []btcec.Signature) {
// 	validSig := false
// 	validatedSigs := *new([]btcec.Signature)
// 	usedKeys := make([]bool, len(b.PublicKeys))
// 	messageBytes := sha256.Sum256([]byte(message))
// 	for _, sigbytes := range *signatures {

// 		signature, err := btcec.ParseDERSignature(sigbytes, btcec.S256())
// 		if err != nil {
// 			fmt.Println("Bad signature encoding")
// 			return false, nil
// 		}

// 		for i, pubKey := range b.PublicKeys {
// 			success := signature.Verify(messageBytes[:], &pubKey)
// 			if success && (usedKeys[i] == false) {
// 				validSig = true
// 				validatedSigs = append(validatedSigs, *signature)
// 				usedKeys[i] = true
// 			}
// 		}
// 	}

// 	if validSig == false {
// 		return false, nil
// 	}
// 	if len(validatedSigs) < b.Threshold {
// 		return false, nil
// 	}
// 	return validSig, validatedSigs
// }

// func (b *SecP256k1Output) ToBytes() []byte {
// 	store := ProofElementStore.SECPProofElementStore{}
// 	store.Name = b.ProofName
// 	store.Data = b.Data
// 	store.SupercededBy = b.SupercededBy
// 	store.Threshold = int32(b.Threshold)
// 	switch b.State {
// 	case Initialized:
// 		store.State = ProofElementStore.SECPProofElementStore_Initialized
// 	case Signed:
// 		store.State = ProofElementStore.SECPProofElementStore_Signed
// 	case Revoked:
// 		store.State = ProofElementStore.SECPProofElementStore_Revoked
// 	case Superceded:
// 		store.State = ProofElementStore.SECPProofElementStore_Superceded
// 	}

// 	for _, key := range b.PublicKeys {
// 		store.PublicKeys = append(store.PublicKeys, key.SerializeCompressed())
// 	}
// 	for _, sigs := range b.Signatures {
// 		store.Signatures = append(store.Signatures, sigs.Serialize())
// 	}
// 	metastore := ProofElementStore.ProofElementStore{}
// 	metastore.Type = ProofElementStore.ProofElementStore_SECP
// 	metastore.Secp = &store

// 	bufferBytes, err := proto.Marshal(&metastore)
// 	if err != nil {
// 		fmt.Println(err)
// 	}
// 	return bufferBytes
// }

// func (b *SecP256k1Output) FromBytes(bits []byte) error {
// 	metastore := ProofElementStore.ProofElementStore{}
// 	err := proto.Unmarshal(bits, &metastore)
// 	if err != nil {
// 		return err
// 	}
// 	if metastore.Type != ProofElementStore.ProofElementStore_SECP {
// 		return errors.New("Expected SECP proof")
// 	}
// 	store := metastore.Secp
// 	b.ProofName = store.Name
// 	b.Data = store.Data
// 	b.SupercededBy = store.SupercededBy
// 	b.Threshold = int(store.Threshold)
// 	switch store.State {
// 	case ProofElementStore.SECPProofElementStore_Initialized:
// 		b.State = Initialized
// 	case ProofElementStore.SECPProofElementStore_Signed:
// 		b.State = Signed
// 	case ProofElementStore.SECPProofElementStore_Revoked:
// 		b.State = Revoked
// 	case ProofElementStore.SECPProofElementStore_Superceded:
// 		b.State = Superceded
// 	}
// 	for _, key := range store.PublicKeys {
// 		publicKey, err := btcec.ParsePubKey(key, btcec.S256())
// 		if err != nil {
// 			return err
// 		}
// 		b.PublicKeys = append(b.PublicKeys, *publicKey)
// 	}
// 	for _, sig := range store.Signatures {
// 		signature, err := btcec.ParseSignature(sig, btcec.S256())
// 		if err != nil {
// 			return err
// 		}
// 		b.Signatures = append(b.Signatures, *signature)
// 	}
// 	return nil
// }

func (b *SecP256k1Output) ToJSON() []byte {
	type JSONBracket struct {
		Owners    []string
		Threshold int
		Data      string
		Creator   string
		Amount    int
	}
	jsonBracket := JSONBracket{}

	for _, pubKey := range b.Owners {
		jsonBracket.Owners = append(jsonBracket.Owners, hex.EncodeToString(pubKey.SerializeCompressed()))
	}
	jsonBracket.Threshold = b.Threshold
	jsonBracket.Data = b.Data
	jsonBracket.Amount = b.Amount

	jsonstring, err := json.Marshal(jsonBracket)
	if err != nil {
		return nil
	}
	return jsonstring
}
