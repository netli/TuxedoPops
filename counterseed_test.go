package main

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"encoding/hex"

	"github.com/golang/protobuf/proto"

	"github.com/btcsuite/btcd/btcec"
	"github.com/hyperledger/fabric/core/chaincode/shim"
	txcache "github.com/skuchain/tuxpops2/TXCache"
)

/*
	checkCounterSeedChange generates 150 create transactions and checks that the counterseed changes at the appropriate time.
	Can be called in a loop.
*/
func checkCounterSeedChange(t *testing.T, stub *shim.MockStub) {
	originalCounterseed, err := stub.GetState("CounterSeed")
	if err != nil {
		HandleError(t, fmt.Errorf("error retrieving counterseed through counterseed query"))
		t.FailNow()
	}
	txCache := txcache.TXCache{}
	txCacheBytes, err := stub.GetState("TxCache")
	if err != nil {
		HandleError(t, err)
		t.FailNow()
	}
	proto.Unmarshal(txCacheBytes, &txCache)
	//create up to 150 popcodes
	for i := len(txCache.Cache); i < 150; i++ {
		//create a new set of keys
		user, err := generateKeys()
		if err != nil {
			HandleError(t, fmt.Errorf("error generating user: (%v)\n", err.Error()))
		}

		popcode, err := generateKeys()
		if err != nil {
			HandleError(t, fmt.Errorf("error generating popcode: (%v)\n", err.Error()))
		}

		popcode.counter, err = getCounter(stub, popcode)
		if err != nil {
			HandleError(t, fmt.Errorf("error retrieving counterseed: (%v)", err.Error()))
			t.FailNow()
		}

		//mint transaction with keys and counterseed
		mint(t, stub, user, popcode, "Test Data", "Test Asset", 10)
		//check counterseed
		counterseed, err := stub.GetState("CounterSeed")
		if err != nil {
			HandleError(t, fmt.Errorf("error retrieving counterseed through call to getState"))
		}

		txCache := txcache.TXCache{}
		txCacheBytes, err := stub.GetState("TxCache")
		if err != nil {
			HandleError(t, err)
		}
		proto.Unmarshal(txCacheBytes, &txCache)

		fmt.Printf("\n\nCOUNTERSEEDSTRING: (%s)\ni: (%d)\nTXCACHELEN: (%d)\n\n\n",
			hex.EncodeToString(counterseed), i, len(txCache.Cache))

		//check for correct counterSeed value
		if (i < 101) && (hex.EncodeToString(counterseed) != hex.EncodeToString(originalCounterseed)) {
			HandleError(t, fmt.Errorf("\nCounterseed got:\n(%s)\nwant:\n(%s)\n",
				hex.EncodeToString(counterseed), hex.EncodeToString(originalCounterseed)))

			t.FailNow()
		}
		if expected := sha256.Sum256(originalCounterseed); i > 101 &&
			(hex.EncodeToString(counterseed) != hex.EncodeToString(expected[:])) {

			HandleError(t, fmt.Errorf("\nCounterseed got:\n(%s)\nwant:\n(%s)\n",
				hex.EncodeToString(counterseed), hex.EncodeToString(expected[:])))

			t.FailNow()
		}
	}
}

//generates and returns SHA256 private key string
func newPrivateKeyString() (string, error) {
	privKey, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		return "", fmt.Errorf("Error generating private key\n")
	}
	privKeyBytes := privKey.Serialize()
	privKeyString := hex.EncodeToString(privKeyBytes)
	return privKeyString, nil
}

//generates and returns SHA256 public key string fromessage private key string input
func newPubKeyString(privKeyString string) (string, error) {
	privKeyBytes, err := hex.DecodeString(privKeyString)
	if err != nil {
		return "", fmt.Errorf("error decoding private key string (%s)", privKeyString)
	}
	_, pubKey := btcec.PrivKeyFromBytes(btcec.S256(), privKeyBytes)
	pubKeyBytes := pubKey.SerializeCompressed()
	pubkKeyString := hex.EncodeToString(pubKeyBytes)
	return pubkKeyString, nil
}

//generates and returns first forty characters of sha256 hash of public key string
func newAddress(pubKeyStr string) string {
	pubKeyBytes, err := hex.DecodeString(pubKeyStr)
	if err != nil {
		fmt.Printf("error decoding pubkeystring (%s)", pubKeyStr)
	}
	hasher := sha256.New()
	hasher.Write(pubKeyBytes)
	hashedPubKeyBytes := []byte{}
	hashedPubKeyBytes = hasher.Sum(hashedPubKeyBytes)
	hashedPubKeyString := hex.EncodeToString(hashedPubKeyBytes[0:20])
	address := hashedPubKeyString
	return address
}

func generateKeys() (*keyInfo, error) {
	var err error
	keys := new(keyInfo)
	keys.privKeyStr, err = newPrivateKeyString()
	if err != nil {
		fmt.Printf("error generating private key: %v", err.Error())
		return nil, fmt.Errorf("error generating private key: %v", err.Error())
	}
	keys.pubKeyStr, err = newPubKeyString(keys.privKeyStr)
	if err != nil {
		fmt.Printf("error generating public key: %v", err.Error())
		return nil, fmt.Errorf("error generating public key: %v", err.Error())
	}
	keys.address = newAddress(keys.pubKeyStr)
	return keys, nil
}
