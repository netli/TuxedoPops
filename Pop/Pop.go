package Pop

import (
	"crypto/sha256"
	"fmt"
	"strconv"

	"encoding/hex"
	"encoding/json"

	"github.com/btcsuite/btcd/btcec"
	"github.com/golang/protobuf/proto"
	"github.com/skuchain/TuxedoPops/OTX"
	"github.com/skuchain/TuxedoPops/TuxedoPopsStore"
)

type Pop struct {
	Address string
	PubKey  btcec.PublicKey
	Counter []byte
	Outputs []OTX.SecP256k1Output
}

func (p *Pop) verifyPopSigs(idx int, m string, ownerSigs [][]byte, PopSig []byte) error {

	mDigest := sha256.Sum256([]byte(m))

	if idx < 0 || idx >= len(p.Outputs) {
		return fmt.Errorf("Invalid Source index %d\n %s\n", idx, p.ToJSON())
	}

	otx := p.Outputs[idx]
	if len(otx.Owners) > 0 {
		usedKeys := make([]bool, len(otx.Owners))
		validOwnerSigs := 0
		for _, sigbytes := range ownerSigs {
			signature, err := btcec.ParseDERSignature(sigbytes, btcec.S256())
			if err != nil {
				return fmt.Errorf("Bad Owner signature encoding %v", sigbytes)
			}

			for i, ownerKey := range otx.Owners {
				if usedKeys[i] {
					continue
				}
				success := signature.Verify(mDigest[:], &ownerKey)
				if success {
					usedKeys[i] = true
					validOwnerSigs++
					break
				}
				if i == len(otx.Owners)-1 {
					return fmt.Errorf("Invalid Signature %s on %s", hex.EncodeToString(signature.Serialize()), m)
				}
			}
		}
		if validOwnerSigs < otx.Threshold {
			return fmt.Errorf("\n\nInsufficient Signatures (validOwnerSigs < otx.Threshold).\nnumber of valid owner sigs: (%d)\notx.Threshold: (%d)\nownerSigs: (%v)\n\n\n", validOwnerSigs, otx.Threshold, ownerSigs)
		}
	}

	signature, err := btcec.ParseDERSignature(PopSig, btcec.S256())
	if err != nil {
		return fmt.Errorf("Bad popcode signature encoding %v", PopSig)
	}
	success := signature.Verify(mDigest[:], &p.PubKey)
	if !success {
		return fmt.Errorf("Invalid Pop Signature %+v Pubkey %s Message %s", signature, hex.EncodeToString(p.PubKey.SerializeCompressed()), m)
	}
	return nil
}

func (p *Pop) CreateOutput(amount int, assetType string, data string, creatorKeyBytes []byte, creatorSig []byte) error {

	//deserialize public key bytes into a public key object
	creatorKey, err := btcec.ParsePubKey(creatorKeyBytes, btcec.S256())

	if err != nil {
		return fmt.Errorf("Invalid Creator key")
	}

	//DER is a standard for serialization
	//parsing DER signature from bitcoin curve into a signature object
	signature, err := btcec.ParseDERSignature(creatorSig, btcec.S256())
	if err != nil {
		fmt.Printf("Bad Creator signature encoding %+v", p)

		return fmt.Errorf("Bad Creator signature encoding %+v", p)
	}

	//FIXME add Value to the signature
	message := hex.EncodeToString(p.Counter) + ":" + p.Address + ":" + strconv.FormatInt(int64(amount), 10) + ":" + assetType + ":" + data

	messageBytes := sha256.Sum256([]byte(message))

	//try to verify the signature (most likely failure is that the wrong thing has been signed (maybe the counterseed changed or the message you signed and the message you verified are not the same))
	success := signature.Verify(messageBytes[:], creatorKey)
	if !success {
		fmt.Printf("Invalid Creator Signature %s \n Pubkey:%v \n ", message, creatorKey)
		return fmt.Errorf("Invalid Creator Signature %s\n Pubkey:%v ", message, creatorKey)
	}

	output := OTX.New(creatorKey, amount, assetType, data, p.Counter)

	p.Outputs = append(p.Outputs, *output)
	newCounter := sha256.Sum256(p.Counter)
	p.Counter = newCounter[:]
	return nil
}

func (p *Pop) CreateOutputFromSources(amount int, assetType string, data string, creatorKeyBytes []byte, creatorSig []byte, counter []byte) error {

	creatorKey, err := btcec.ParsePubKey(creatorKeyBytes, btcec.S256())

	if err != nil {
		return fmt.Errorf("Invalid Creator key")
	}

	signature, err := btcec.ParseDERSignature(creatorSig, btcec.S256())
	if err != nil {
		fmt.Println("Bad Creator signature encoding")

		return fmt.Errorf("Bad Creator signature encoding")
	}

	message := hex.EncodeToString(p.Counter) + ":" + strconv.FormatInt(int64(amount), 10) + ":" + assetType + ":" + data
	messageBytes := sha256.Sum256([]byte(message))

	success := signature.Verify(messageBytes[:], creatorKey)
	if !success {
		fmt.Println("Invalid Creator signature")
		return fmt.Errorf("Invalid Creator signature")
	}

	output := OTX.New(creatorKey, amount, assetType, data, counter)
	p.Outputs = append(p.Outputs, *output)
	newCounter := sha256.Sum256(p.Counter)
	p.Counter = newCounter[:]
	return nil
}

func (p *Pop) UnitizeOutput(idx int, amounts []int, data string, dest *Pop, ownerSigs [][]byte, PopPubkey []byte, PopSig []byte) error {

	pubkey, err := btcec.ParsePubKey(PopPubkey, btcec.S256())

	p.PubKey = *pubkey

	if err != nil {
		return fmt.Errorf("Invalid Creator key")
	}
	keyDigest := sha256.Sum256(PopPubkey)
	PopAddress := hex.EncodeToString(keyDigest[:20])
	if PopAddress != p.Address {
		return fmt.Errorf("Invalid Pop Public Key")
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

	m := hex.EncodeToString(p.Counter) + ":" + dest.Address + ":" + data
	m += ":" + strconv.FormatInt(int64(idx), 10)
	for _, amount := range amounts {
		m += ":" + strconv.FormatInt(int64(amount), 10)
	}
	fmt.Printf("\n\nFROM POP.GO\nUnitize Message: %s\n\n", m)
	err = p.verifyPopSigs(idx, m, ownerSigs, PopSig)
	if err != nil {
		return err
	}

	for _, amount := range amounts {

		//I'm pretty sure this is a copy not a reference
		destOut := p.Outputs[idx]
		destOut.PrevCounter = p.Counter
		newCounter := sha256.Sum256(p.Counter)
		p.Counter = newCounter[:]
		destOut.Data = data
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
	newCounter := sha256.Sum256(p.Counter)
	p.Counter = newCounter[:]
	return nil
}

type SourceOutput interface {
	Idx() int
	Amount() int
}

func (p *Pop) CombineOutputs(sources []SourceOutput, ownerSigs [][]byte, PopPubKey []byte, PopSig []byte,
	createdAmount int, recipeName string, recipe TuxedoPopsStore.Recipe, data string, creatorPublicKeyBytes []byte, creatorSigBytes []byte) error {

	// create public key object from PopPubKey
	pubkey, err := btcec.ParsePubKey(PopPubKey, btcec.S256())

	p.PubKey = *pubkey

	if err != nil {
		return fmt.Errorf("Invalid Pop key")
	}

	//generate popcode address from public key object
	keyDigest := sha256.Sum256(PopPubKey)
	PopAddress := hex.EncodeToString(keyDigest[:20])
	if PopAddress != p.Address {
		return fmt.Errorf("Invalid Pop Public Key")
	}

	//create public key object from creatorPublicKeyBytes
	creatorPublicKey, err := btcec.ParsePubKey(creatorPublicKeyBytes, btcec.S256())

	if err != nil {
		return fmt.Errorf("Invalid Creator key")
	}

	//creatorSigBytes should be the signature of the following message
	m := hex.EncodeToString(p.Counter)
	m += ":" + recipeName
	for _, source := range sources {
		m += ":" + strconv.FormatInt(int64(source.Idx()), 10)
		m += ":" + strconv.FormatInt(int64(source.Amount()), 10)
	}
	m += ":" + strconv.FormatInt(int64(createdAmount), 10)
	m += ":" + data

	fmt.Printf("\n\nFROM POP.GO\nCombine Message: %s\n\n", m)
	mDigest := sha256.Sum256([]byte(m))

	sourceAmounts := make(map[string]int)

	for _, source := range sources {

		err = p.verifyPopSigs(source.Idx(), m, ownerSigs, PopSig)
		if err != nil {
			return err
		}

		p.Outputs[source.Idx()].Amount -= source.Amount()
		sourceAmounts[p.Outputs[source.Idx()].Type] += source.Amount()
	}

	/*
		copy nonzero values and assign p.outputs to the new array.
		make array of ouputs. If outputs.amount is greater than
		need to make a new array that's a copy of the first one and isn't edited as we iterate.
	*/
	filteredArray := make([]OTX.SecP256k1Output, 0)

	for idx := range p.Outputs {

		if p.Outputs[idx].Amount < 0 {
			return fmt.Errorf("Insufficient balance in index %d", idx)
		}
		if p.Outputs[idx].Amount != 0 {
			filteredArray = append(filteredArray, p.Outputs[idx])
		}
	}

	p.Outputs = filteredArray

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
	for _, ingredient := range recipe.Ingredients {
		sourceAmt := sourceAmounts[ingredient.Type]
		if (int64(sourceAmt) / ingredient.Numerator * ingredient.Denominator) != int64(createdAmount) {
			return fmt.Errorf("Ratio invalid for %s", ingredient.Type)
		}
	}

	output := OTX.New(creatorPublicKey, createdAmount, recipe.CreatedType, data, p.Counter)
	p.Outputs = append(p.Outputs, *output)
	newCounter := sha256.Sum256(p.Counter)
	p.Counter = newCounter[:]
	return nil
}

func (p *Pop) SetOwner(idx int, threshold int, data string, newOwnersBytes [][]byte, ownerSigs [][]byte, PopPubKey []byte, PopSig []byte) error {

	pubkey, err := btcec.ParsePubKey(PopPubKey, btcec.S256())

	p.PubKey = *pubkey

	if err != nil {
		return fmt.Errorf("Invalid Creator key %v", PopPubKey)
	}
	keyDigest := sha256.Sum256(PopPubKey)
	PopAddress := hex.EncodeToString(keyDigest[:20])
	if PopAddress != p.Address {
		return fmt.Errorf("Invalid Pop Public Key for address %v", PopAddress)
	}

	newOwners := make([]btcec.PublicKey, len(newOwnersBytes))

	// Check to see if output is valid
	if idx >= len(p.Outputs) {
		return fmt.Errorf("Invalid index")
	}

	for i, newowns := range newOwnersBytes {
		pubKey, err := btcec.ParsePubKey(newowns, btcec.S256())
		if err != nil {
			return fmt.Errorf("Invalid New Owner PublicKey")
		}
		newOwners[i] = *pubKey
	}
	//Retrieve output

	m := hex.EncodeToString(p.Counter)
	m += ":" + strconv.FormatInt(int64(idx), 10)
	if threshold > 0 {
		m += ":" + strconv.FormatInt(int64(threshold), 10)
	}
	m += ":" + data
	for _, newO := range newOwners {
		if newO.Curve != nil && newO.X != nil && newO.Y != nil {
			m += ":"
			m += hex.EncodeToString(newO.SerializeCompressed())
		}
	}
	// fmt.Printf("Verify message %s \n", m)

	err = p.verifyPopSigs(idx, m, ownerSigs, PopSig)
	if err != nil {
		return err
	}
	p.Outputs[idx].Owners = newOwners
	p.Outputs[idx].Data = data
	p.Outputs[idx].PrevCounter = p.Counter

	if threshold > 0 {
		p.Outputs[idx].Threshold = threshold
	} else {
		p.Outputs[idx].Threshold = len(newOwners)
	}
	digest := sha256.Sum256(p.Counter)
	p.Counter = digest[:]
	return nil
}

func (p *Pop) ToBytes() []byte {
	store := TuxedoPopsStore.TuxedoPops{}
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

func (p *Pop) FromBytes(buf []byte) error {
	store := TuxedoPopsStore.TuxedoPops{}
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

func (p *Pop) ToJSON() []byte {
	type JSONPop struct {
		Address string
		Counter string
		Outputs []string
	}
	jsonPop := JSONPop{}
	jsonPop.Address = p.Address
	jsonPop.Counter = hex.EncodeToString(p.Counter)
	for _, o := range p.Outputs {
		jsonPop.Outputs = append(jsonPop.Outputs, string(o.ToJSON()))
	}
	jsonstring, err := json.Marshal(jsonPop)
	if err != nil {
		return nil
	}
	return jsonstring
}
