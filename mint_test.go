package main

import (
	"crypto/sha256"
	"fmt"
	"strconv"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/skuchain/TuxedoPops/TuxedoPopsTX"

	"encoding/hex"

	"github.com/btcsuite/btcd/btcec"
	"github.com/hyperledger/fabric/core/chaincode/shim"
)

func testMint(t *testing.T, stub *shim.MockStub, popcodes *popcodes, users *users) {
	//MINT
	balance := getBalance(t, stub, popcodes.popcode1)
	fmt.Printf("\n\n\nbalance before mint (%v)\n\n\n", balance)
	prevCounter := balance.Counter
	prevNumberOfOutputs := len(balance.Outputs)
	data := "data"
	createdType := "Water"
	amount := 100

	mint(t, stub, users.user1, popcodes.popcode1, data, createdType, amount)
	balance = getBalance(t, stub, popcodes.popcode1)
	fmt.Printf("\n\n\nbalance on popcode (%v)\ncounter: (%v)\noutputs: (%v)\n\n",
		balance.Address, balance.Counter, balance.Outputs)

	if prevCounter == balance.Counter {
		HandleError(t, fmt.Errorf("counter of address (%s) did not change after call to mint. Counter: (%s)",
			balance.Address, balance.Counter))
		t.FailNow()
	}
	if len(balance.Outputs) != prevNumberOfOutputs+1 {
		HandleError(t, fmt.Errorf("number of outputs of popcode with address (%s)"+
			" did not increase by one after create transaction", popcodes.popcode1))
		t.FailNow()
	}
}

func generateCreateSig(CounterSeedStr string, amount int, assetType string,
	data string, addr string, privateKeyStr string) string {

	privKeyByte, _ := hex.DecodeString(privateKeyStr)

	privKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), privKeyByte)

	message := CounterSeedStr + ":" + addr + ":" +
		strconv.FormatInt(int64(amount), 10) + ":" + assetType + ":" + data
	fmt.Println("Signed Message")
	fmt.Println(message)
	messageBytes := sha256.Sum256([]byte(message))
	sig, _ := privKey.Sign(messageBytes[:])
	return hex.EncodeToString(sig.Serialize())
}

//hardCodedMint performs a create transaction with all parameters (other than counterseed) hard coded rather than taken as arguments.
func hardCodedMint(t *testing.T, stub *shim.MockStub, counterSeed string) {
	createArgs := TuxedoPopsTX.CreateTX{}
	createArgs.Address = "74ded2036e988fc56e3cff77a40c58239591e921"
	createArgs.Amount = 10
	pubKeyBytes, err := hex.DecodeString("03cc7d40833fdf46e05a7f86a6c9cf8a697a129fbae0676ad6bad71f163ea22b26")
	if err != nil {
		HandleError(t, err)
	}
	createArgs.CreatorPubKey = pubKeyBytes
	hexCreatorSig := generateCreateSig(counterSeed, 10, "Test Asset", "Test Data",
		"74ded2036e988fc56e3cff77a40c58239591e921", "7ff1ac3d9dfc56315ee610d0a15609d13c399cf9c92ba2e32e7b1d25ea5c9494")

	createArgs.CreatorSig, err = hex.DecodeString(hexCreatorSig)
	if err != nil {
		HandleError(t, err)
	}
	createArgs.Data = "Test Data"
	createArgs.Type = "Test Asset"
	createArgBytes, err := proto.Marshal(&createArgs)
	createArgBytesStr := hex.EncodeToString(createArgBytes)
	_, err = stub.MockInvoke("3", "create", []string{createArgBytesStr})
	if err != nil {
		HandleError(t, err)
	}
}

func mint(t *testing.T, stub *shim.MockStub, user *keyInfo, popcode *keyInfo,
	data string, createdType string, amount int) {

	createArgs := TuxedoPopsTX.CreateTX{}
	createArgs.Address = popcode.address
	createArgs.Amount = int32(amount)
	createArgs.Data = data
	createArgs.Type = createdType

	creatorPubKeyBytes, err := hex.DecodeString(user.pubKeyStr)
	if err != nil {
		HandleError(t, err)
	}
	createArgs.CreatorPubKey = creatorPubKeyBytes
	popcode.counter, err = getCounter(stub, popcode)
	if err != nil {
		HandleError(t, fmt.Errorf("Error getting counterseed in altMint: (%s)", err.Error()))
		t.FailNow()
	}
	hexCreatorSig := generateCreateSig(popcode.counter, amount, createdType, data, popcode.address, user.privKeyStr)

	createArgs.CreatorSig, err = hex.DecodeString(hexCreatorSig)
	if err != nil {
		HandleError(t, err)
	}

	createArgBytes, err := proto.Marshal(&createArgs)
	createArgBytesStr := hex.EncodeToString(createArgBytes)
	_, err = stub.MockInvoke("3", "create", []string{createArgBytesStr})
	if err != nil {
		HandleError(t, err)
	}
}
