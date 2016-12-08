package Popcodes

import (
	"crypto/sha256"
	"fmt"

	"encoding/hex"

	"github.com/btcsuite/btcd/btcec"
	"github.com/skuchain/popcodes_utxo/OTX"
)

type Popcode struct {
	PubKey  btcec.PublicKey
	Counter []byte
	Outputs []OTX.SecP256k1Output
}

func (p *Popcode) CreateOutput(amount int, data string, creatorKey btcec.PublicKey, creatorSig []byte) error {

	signature, err := btcec.ParseDERSignature(creatorSig, btcec.S256())
	if err != nil {
		fmt.Println("Bad signature encoding")
		return error.Error("Bad signature encoding")
	}

	message := hex.EncodeToString(p.Counter) + ":" + hex.EncodeToString(p.PubKey.SerializeCompressed())
	messageBytes := sha256.Sum256([]byte(message))

	success := signature.Verify(messageBytes[:], &creatorKey)
	if !success {
		fmt.Println("Bad signature encoding")
		return error.Error("Bad signature encoding")
	}

	_ := len(p.Outs)
	output := OTX.SecP256k1Output{}
	p.Outputs = append(p.Outputs, output)
	p.Counter = sha256.Sum256(p.Counter)[:]
	return nil
}

func (p *Popcode) SetOwner(idx int, owner []btcec.PublicKey) {

}

func (p *Popcode) Transfer(idx int, dest *Popcode, transfer_sig []byte) {

}
