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
	"github.com/skuchain/TuxedoPops/TuxedoPopsStore"
)

type SecP256k1Output struct {
	Owners      []btcec.PublicKey
	Threshold   int
	Type        string
	Amount      int
	Creator     *btcec.PublicKey
	Data        string
	PrevCounter []byte
}

func New(creator *btcec.PublicKey, amount int, assetType string, TxData string, counter []byte) *SecP256k1Output {
	code := SecP256k1Output{}
	code.Type = assetType
	code.Amount = amount
	code.Creator = creator
	code.Data = TxData
	copy(code.PrevCounter, counter)
	return &code
}

//PubKeys hello
func (b *SecP256k1Output) PubKeys() []string {
	output := *new([]string)
	for _, key := range b.Owners {
		output = append(output, hex.EncodeToString(key.SerializeCompressed()))
	}
	return output
}

func (b *SecP256k1Output) ToProtoBuf() *TuxedoPopsStore.OTX {
	buf := TuxedoPopsStore.OTX{}
	buf.Amount = int64(b.Amount)
	buf.Creator = b.Creator.SerializeCompressed()
	buf.Type = b.Type
	buf.Data = b.Data
	buf.PrevCounter = b.PrevCounter
	buf.Threshold = int64(b.Threshold)
	for _, owner := range b.Owners {
		if owner.Curve != nil && owner.X != nil && owner.Y != nil {

			buf.Owners = append(buf.Owners, owner.SerializeCompressed())
		}
	}
	return &buf
}

func (b *SecP256k1Output) FromProtoBuf(buf TuxedoPopsStore.OTX) error {
	b.Amount = int(buf.Amount)
	creatorKey, err := btcec.ParsePubKey(buf.Creator, btcec.S256())
	if err != nil {
		return err
	}
	b.Creator = creatorKey
	b.Type = buf.Type
	b.Data = buf.Data
	b.Threshold = int(buf.Threshold)
	b.PrevCounter = buf.PrevCounter
	for _, ownerBuf := range buf.Owners {
		ownerKey, err := btcec.ParsePubKey(ownerBuf, btcec.S256())
		if err != nil {
			return err
		}
		b.Owners = append(b.Owners, *ownerKey)

	}
	return nil
}

func (b *SecP256k1Output) ToJSON() []byte {
	type JSONOTX struct {
		Owners      []string
		Threshold   int
		Data        string
		Type        string
		PrevCounter string
		Creator     string
		Amount      int64
	}
	jsonOTX := JSONOTX{}

	for _, pubKey := range b.Owners {
		jsonOTX.Owners = append(jsonOTX.Owners, hex.EncodeToString(pubKey.SerializeCompressed()))
	}
	jsonOTX.Threshold = b.Threshold
	jsonOTX.Data = b.Data
	jsonOTX.Type = b.Type
	jsonOTX.Amount = int64(b.Amount)
	jsonOTX.Creator = hex.EncodeToString(b.Creator.SerializeCompressed())
	jsonOTX.PrevCounter = hex.EncodeToString(b.PrevCounter)

	jsonstring, err := json.Marshal(jsonOTX)
	if err != nil {
		return nil
	}
	return jsonstring
}
