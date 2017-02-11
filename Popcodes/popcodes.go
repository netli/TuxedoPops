package popcodes

import (
	"crypto/sha256"
	"fmt"
	"strconv"

	"encoding/base64"
	"encoding/hex"
	"encoding/json"

	"github.com/btcsuite/btcd/btcec"
	"github.com/golang/protobuf/proto"
	"github.com/skuchain/popcodes_utxo/OTX"
	"github.com/skuchain/popcodes_utxo/PopcodesStore"
)

type Popcode struct {
	Address string
	PubKey  btcec.PublicKey
	Counter []byte
	Outputs []OTX.SecP256k1Output
}

func (p *Popcode) verifyPopcodeSigs(idx int, mDigest []byte, ownerSigs [][]byte, popcodeSig []byte) error {
	otx := p.Outputs[idx]
	if len(otx.Owners) > 0 {
		usedKeys := make([]bool, len(otx.Owners))
		validOwnerSigs := 0
		for _, sigbytes := range ownerSigs {
			signature, err := btcec.ParseDERSignature(sigbytes, btcec.S256())
			if err != nil {
				fmt.Println("Bad signature encoding")
				return fmt.Errorf("Bad signature encoding")
			}

			for i, pubKey := range otx.Owners {
				success := signature.Verify(mDigest[:], &pubKey)
				if success && (usedKeys[i] == false) {
					usedKeys[i] = true
					validOwnerSigs++
				}
			}
		}
		if validOwnerSigs < otx.Threshold {
			return fmt.Errorf("Insufficient Signatures")
		}
	}

	signature, err := btcec.ParseDERSignature(popcodeSig, btcec.S256())
	if err != nil {
		fmt.Println("Bad signature encoding")
		return fmt.Errorf("Bad signature encoding")
	}
	success := signature.Verify(mDigest[:], &p.PubKey)
	if !success {
		return fmt.Errorf("Invalid Popcode Signature")
	}
	return nil
}

func (p *Popcode) CreateOutput(amount int, data string, creatorKeyBytes []byte, creatorSig []byte) error {

	creatorKey, err := btcec.ParsePubKey(creatorKeyBytes, btcec.S256())

	if err != nil {
		return fmt.Errorf("Invalid Creator key")
	}

	signature, err := btcec.ParseDERSignature(creatorSig, btcec.S256())
	if err != nil {
		fmt.Println("Bad signature encoding")

		return fmt.Errorf("Bad signature encoding")
	}

	message := hex.EncodeToString(p.Counter) + ":" + hex.EncodeToString(p.PubKey.SerializeCompressed()) + ":" + strconv.FormatInt(int64(amount), 10) + ":" + data
	messageBytes := sha256.Sum256([]byte(message))

	success := signature.Verify(messageBytes[:], creatorKey)
	if !success {
		fmt.Println("Bad signature encoding")
		return fmt.Errorf("Bad signature encoding")
	}

	output := OTX.New(*creatorKey, amount, data)
	p.Outputs = append(p.Outputs, *output)
	newCounter := sha256.Sum256(p.Counter)
	p.Counter = newCounter[:]
	return nil
}

func (p *Popcode) CreateOutputFromSources(amount int, data string, creatorKeyBytes []byte, creatorSig []byte) error {

	creatorKey, err := btcec.ParsePubKey(creatorKeyBytes, btcec.S256())

	if err != nil {
		return fmt.Errorf("Invalid Creator key")
	}

	signature, err := btcec.ParseDERSignature(creatorSig, btcec.S256())
	if err != nil {
		fmt.Println("Bad signature encoding")

		return fmt.Errorf("Bad signature encoding")
	}

	message := hex.EncodeToString(p.Counter) + ":" + hex.EncodeToString(p.PubKey.SerializeCompressed()) + ":" + strconv.FormatInt(int64(amount), 10) + ":" + data
	messageBytes := sha256.Sum256([]byte(message))

	success := signature.Verify(messageBytes[:], creatorKey)
	if !success {
		fmt.Println("Bad signature encoding")
		return fmt.Errorf("Bad signature encoding")
	}

	output := OTX.New(*creatorKey, amount, data)
	p.Outputs = append(p.Outputs, *output)
	newCounter := sha256.Sum256(p.Counter)
	p.Counter = newCounter[:]
	return nil
}

func (p *Popcode) UnitizeOutput(idx int, amounts []int, dest *Popcode, ownerSigs [][]byte, popcodePubkey []byte, popcodeSig []byte) error {

	pubkey, err := btcec.ParsePubKey(popcodePubkey, btcec.S256())

	p.PubKey = *pubkey

	if err != nil {
		return fmt.Errorf("Invalid Creator key")
	}
	keyDigest := sha256.Sum256(popcodePubkey)
	popcodeAddress := base64.StdEncoding.EncodeToString(keyDigest[:20])
	if popcodeAddress != p.Address {
		return fmt.Errorf("Invalid Popcode Public Key")
	}

	// Check to see if output is valid
	if idx >= len(p.Outputs) {
		return fmt.Errorf("Invalid index")
	}

	otx := p.Outputs[idx]
	totalAmount := 0
	for _, value := range amounts {
		if value < 0 {
			return fmt.Errorf("Negative outputs are prohibited")
		}
		totalAmount += value
	}
	if otx.Amount < totalAmount {
		return fmt.Errorf("Insufficient amount")
	}
	digest := sha256.Sum256(dest.PubKey.SerializeCompressed())
	dest_address := base64.StdEncoding.EncodeToString(digest[:20])
	m := dest_address
	m += ":" + strconv.FormatInt(int64(idx), 10)
	for _, amount := range amounts {
		m += ":" + strconv.FormatInt(int64(amount), 10)
	}
	mDigest := sha256.Sum256([]byte(m))
	err = p.verifyPopcodeSigs(idx, mDigest[:], ownerSigs, popcodeSig)
	if err != nil {
		return err
	}

	for _, amount := range amounts {

		//I'm pretty sure this is a copy not a reference
		destOut := p.Outputs[idx]
		destOut.Amount = amount
		p.Outputs[idx].Amount -= amount
		if p.Outputs[idx].Amount == 0 {
			if idx != (len(p.Outputs) - 1) {
				p.Outputs = append(p.Outputs[:idx], p.Outputs[idx+1:]...)
			} else {
				p.Outputs = p.Outputs[:idx]
			}
		}
		dest.Outputs = append(dest.Outputs, destOut)
	}
	return nil

}

type SourceOutput interface {
	Idx() int
	Amount() int
}

func (p *Popcode) CombineOutputs(sources []SourceOutput, ownerSigs [][]byte, popcodePubKey []byte, popcodeSig []byte, createdAmount int, data string, creatorPublicKeyBytes []byte, creatorSigBytes []byte) error {

	pubkey, err := btcec.ParsePubKey(popcodePubKey, btcec.S256())

	p.PubKey = *pubkey

	if err != nil {
		return fmt.Errorf("Invalid Popcode key")
	}

	keyDigest := sha256.Sum256(popcodePubKey)
	popcodeAddress := base64.StdEncoding.EncodeToString(keyDigest[:20])
	if popcodeAddress != p.Address {
		return fmt.Errorf("Invalid Popcode Public Key")
	}

	creatorPublicKey, err := btcec.ParsePubKey(creatorPublicKeyBytes, btcec.S256())

	if err != nil {
		return fmt.Errorf("Invalid Creator key")
	}

	m := ""
	for _, source := range sources {
		m += ":" + strconv.FormatInt(int64(source.Idx()), 10)
		m += ":" + strconv.FormatInt(int64(source.Amount()), 10)

	}

	m += ":" + strconv.FormatInt(int64(createdAmount), 10)
	m += ":" + data

	mDigest := sha256.Sum256([]byte(m))

	for _, source := range sources {

		err = p.verifyPopcodeSigs(source.Idx(), mDigest[:], ownerSigs, popcodeSig)
		if err != nil {
			return err
		}
		p.Outputs[source.Idx()].Amount -= source.Amount()
		if p.Outputs[source.Idx()].Amount < 1 {
			return fmt.Errorf("Insufficient balance in index %d", source.Idx())
		}
		if p.Outputs[source.Idx()].Amount == 0 {
			if source.Idx() != (len(p.Outputs) - 1) {
				p.Outputs = append(p.Outputs[:source.Idx()], p.Outputs[source.Idx()+1:]...)
			} else {
				p.Outputs = p.Outputs[:source.Idx()]
			}
		}
	}

	signature, err := btcec.ParseDERSignature(creatorSigBytes, btcec.S256())
	if err != nil {
		fmt.Println("Bad signature encoding")

		return fmt.Errorf("Bad signature encoding")
	}
	success := signature.Verify(mDigest[:], creatorPublicKey)
	if !success {
		fmt.Println("Invalid creator signature")
		return fmt.Errorf("Invalid creator signature")
	}
	output := OTX.New(*creatorPublicKey, createdAmount, data)
	p.Outputs = append(p.Outputs, *output)
	newCounter := sha256.Sum256(p.Counter)
	p.Counter = newCounter[:]
	return nil

}

func (p *Popcode) SetOwner(idx int, threshold int, newOwnersBytes [][]byte, ownerSigs [][]byte, popcodePubKey []byte, popcodeSig []byte) error {

	pubkey, err := btcec.ParsePubKey(popcodePubKey, btcec.S256())

	p.PubKey = *pubkey

	if err != nil {
		return fmt.Errorf("Invalid Creator key")
	}
	keyDigest := sha256.Sum256(popcodePubKey)
	popcodeAddress := base64.StdEncoding.EncodeToString(keyDigest[:20])
	if popcodeAddress != p.Address {
		return fmt.Errorf("Invalid Popcode Public Key")
	}

	newOwners := make([]btcec.PublicKey, len(newOwnersBytes))

	// Check to see if output is valid
	if idx >= len(p.Outputs) {
		return fmt.Errorf("Invalid index")
	}
	// Deserialize new Public keys if any
	for _, newowns := range newOwnersBytes {
		pubKey, err := btcec.ParsePubKey(newowns, btcec.S256())
		if err != nil {
			return fmt.Errorf("Invalid New Owner PublicKey")
		}
		newOwners = append(newOwners, *pubKey)
	}
	//Retrieve output

	m := hex.EncodeToString(p.Counter)
	m += ":" + strconv.FormatInt(int64(idx), 10)
	if threshold > 0 {
		m += ":" + strconv.FormatInt(int64(threshold), 10)
	}
	for _, newO := range newOwners {
		m += ":"
		m += hex.EncodeToString(newO.SerializeCompressed())
	}
	mDigest := sha256.Sum256([]byte(m))

	err = p.verifyPopcodeSigs(idx, mDigest[:], ownerSigs, popcodeSig)
	if err != nil {
		return err
	}
	p.Outputs[idx].Owners = newOwners

	if threshold > 0 {
		p.Outputs[idx].Threshold = threshold
	} else {
		p.Outputs[idx].Threshold = len(newOwners)
	}
	digest := sha256.Sum256(p.Counter)
	p.Counter = digest[:]
	return nil
}

func (p *Popcode) ToBytes() []byte {
	store := PopcodesStore.Popcodes{}
	store.Address = p.Address
	store.Counter = p.Counter
	for _, output := range p.Outputs {
		store.Outputs = append(store.Outputs, output.ToProtoBuf())
	}

	bufferBytes, err := proto.Marshal(&store)
	if err != nil {
		fmt.Println(err)
	}
	return bufferBytes

}

func (p *Popcode) FromBytes(buf []byte) error {
	store := PopcodesStore.Popcodes{}
	err := proto.Unmarshal(buf, &store)
	if err != nil {
		return err
	}
	p.Counter = store.Counter
	p.Address = store.Address
	for _, otx := range store.Outputs {
		out := OTX.SecP256k1Output{}
		out.FromProtoBuf(*otx)
		p.Outputs = append(p.Outputs, out)
	}

	return nil
}

func (p *Popcode) ToJSON() []byte {
	type JSONPopcode struct {
		Address string
		Counter string
		Outputs []string
	}
	jsonPopcode := JSONPopcode{}
	jsonPopcode.Address = p.Address
	jsonPopcode.Counter = hex.EncodeToString(p.Counter)
	for _, o := range p.Outputs {
		jsonPopcode.Outputs = append(jsonPopcode.Outputs, string(o.ToJSON()))
	}
	jsonstring, err := json.Marshal(jsonPopcode)
	if err != nil {
		return nil
	}
	return jsonstring
}
