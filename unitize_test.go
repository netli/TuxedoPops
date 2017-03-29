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

/*
	UNITIZE
	check the following:
		counterseed change,
		change in number of outputs, and
		change in quantity of units in ouputs
*/
func testUnitize(t *testing.T, stub *shim.MockStub, popcodes *popcodes, users *users, owners []*keyInfo) {
	sourceBalance := getBalance(t, stub, popcodes.popcode1)
	//unitize owned output into two outputs in a different popcode
	fmt.Printf("\n\n\nbefore unitize: balance on source popcode (%v)\ncounter: (%v)\noutputs: (%v)\n\n\n",
		sourceBalance.Address, sourceBalance.Counter, sourceBalance.Outputs)
	// prevNumberOfOutputs := len(balance["Outputs"].([]interface{}))
	sourcePrevCounter := sourceBalance.Counter
	destBalance := getBalance(t, stub, popcodes.popcode2)
	fmt.Printf("\n\n\nbefore unitize: balance on destination popcode (%v)\ncounter: (%v)\noutputs: (%v)\n\n\n",
		destBalance.Address, destBalance.Counter, destBalance.Outputs)

	destPrevCounter := destBalance.Counter
	destAmounts := []int32{50, 50}
	data := "data"
	output := 0
	unitize(t, stub, popcodes.popcode1, popcodes.popcode2, owners, data, destAmounts, int32(output))
	sourceBalance = getBalance(t, stub, popcodes.popcode1)
	if sourcePrevCounter != sourceBalance.Counter {
		HandleError(t, fmt.Errorf("counter of source popcode (address: %s) changed after call to unitize. Counter: (%s)",
			sourceBalance.Address, sourceBalance.Counter))
	}
	destBalance = getBalance(t, stub, popcodes.popcode2)
	if destPrevCounter == destBalance.Counter {
		HandleError(t, fmt.Errorf("counter of destination popcode (address: %s) "+
			"did not change after call to unitize. Counter: (%s)", destBalance.Address, destBalance.Counter))
	}

	fmt.Printf("\n\n\nafter unitize: balance on source popcode (%v)\ncounter: (%v)\noutputs: (%v)\n\n",
		sourceBalance.Address, sourceBalance.Counter, sourceBalance.Outputs)
	fmt.Printf("\n\n\nafter unitize: balance on destination popcode (%v)\ncounter: (%v)\noutputs: (%v)\n\n",
		destBalance.Address, destBalance.Counter, destBalance.Outputs)

}

func generateUnitizeSig(CounterSeedStr string, destAddr string, outputIdx int,
	amounts []int, data string, privateKeyStr string) []byte {

	privKeyByte, _ := hex.DecodeString(privateKeyStr)
	privKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), privKeyByte)
	message := CounterSeedStr + ":" + destAddr + ":" + data + ":" + strconv.FormatInt(int64(outputIdx), 10)
	for _, amount := range amounts {
		message += ":" + strconv.FormatInt(int64(amount), 10)
	}
	fmt.Printf("\n\nunitize message: (%s)\n\n", message)

	mDigest := sha256.Sum256([]byte(message))
	sig, _ := privKey.Sign(mDigest[:])
	return sig.Serialize()
}

func hardCodedUnitize(t *testing.T, stub *shim.MockStub, counterSeed string) {
	unitizeArgs := TuxedoPopsTX.Unitize{}
	unitizeArgs.Data = "Test Unitize"
	unitizeArgs.DestAddress = "10734390011641497f489cb475743b8e50d429bb"
	unitizeArgs.DestAmounts = []int32{10}
	unitizeArgs.SourceAddress = "74ded2036e988fc56e3cff77a40c58239591e921"
	unitizeArgs.SourceOutput = 0
	unitizeArgs.PopcodePubKey, _ = hex.DecodeString("02ca4a8c7dc5090f924cde2264af240d76f6d58a5d2d15c8c5f59d95c70bd9e4dc")
	ownerSig := generateUnitizeSig(counterSeed, unitizeArgs.DestAddress, 0, []int{10}, unitizeArgs.Data,
		"7142c92e6eba38de08980eeb55b8c98bb19f8d417795adb56b6c4d25da6b26c5")

	unitizeArgs.OwnerSigs = [][]byte{ownerSig}
	unitizeArgs.PopcodeSig = generateUnitizeSig(counterSeed, unitizeArgs.DestAddress, 0, []int{10},
		unitizeArgs.Data, "94d7fe7308a452fdf019a0424d9c48ba9b66bdbca565c6fa3b1bf9c646ebac20")

	unitizeArgsBytes, _ := proto.Marshal(&unitizeArgs)
	unitizeArgsBytesStr := hex.EncodeToString(unitizeArgsBytes)

	_, err := stub.MockInvoke("4", "unitize", []string{unitizeArgsBytesStr})
	if err != nil {
		HandleError(t, err)
		t.FailNow()
	}
}

func unitize(t *testing.T, stub *shim.MockStub, sourcePopcode *keyInfo,
	destPopcode *keyInfo, owners []*keyInfo, data string, amounts []int32, output int32) {

	unitizeArgs := TuxedoPopsTX.Unitize{}
	unitizeArgs.Data = data
	unitizeArgs.DestAddress = destPopcode.address
	unitizeArgs.DestAmounts = amounts

	unitizeArgs.SourceAddress = sourcePopcode.address
	unitizeArgs.SourceOutput = output
	unitizeArgs.PopcodePubKey, _ = hex.DecodeString(sourcePopcode.pubKeyStr)
	var err error
	sourcePopcode.counter, err = getCounter(stub, sourcePopcode)
	if err != nil {
		HandleError(t, fmt.Errorf("Error getting counter: (%v)\n", err.Error()))
		t.FailNow()
	}
	intAmounts := make([]int, len(amounts))
	for i, amount := range amounts {
		intAmounts[i] = int(amount)
	}

	unitizeArgs.OwnerSigs = [][]byte{}
	for _, owner := range owners {
		ownerSig := generateUnitizeSig(sourcePopcode.counter, unitizeArgs.DestAddress,
			int(output), intAmounts, unitizeArgs.Data, owner.privKeyStr)

		unitizeArgs.OwnerSigs = append(unitizeArgs.OwnerSigs, ownerSig)
	}

	unitizeArgs.PopcodeSig = generateUnitizeSig(sourcePopcode.counter, unitizeArgs.DestAddress,
		int(output), intAmounts, unitizeArgs.Data, sourcePopcode.privKeyStr)

	unitizeArgsBytes, _ := proto.Marshal(&unitizeArgs)
	unitizeArgsBytesStr := hex.EncodeToString(unitizeArgsBytes)

	_, err = stub.MockInvoke("4", "unitize", []string{unitizeArgsBytesStr})
	if err != nil {
		HandleError(t, err)
		t.FailNow()
	}
}
