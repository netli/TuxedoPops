package main

import (
	"crypto/sha256"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/skuchain/TuxedoPops/TuxedoPopsTX"

	"encoding/hex"

	"github.com/btcsuite/btcd/btcec"
	"github.com/hyperledger/fabric/core/chaincode/shim"
)

func testPossess(t *testing.T, stub *shim.MockStub, popcodes *popcodes, users *users, newOwners *[]*keyInfo) {
	/*
		POSSESS
		perform initial possess
		one new owner
	*/
	output := 0
	balance := getBalance(t, stub, popcodes.popcode1)

	/*
		check if outputs exist in the popcode. If not, mint an output with 100 units water
	*/
	if len(balance.Outputs) == 0 {
		data := "data"
		createdType := "Water"
		amount := 100
		mint(t, stub, users.user1, popcodes.popcode1, data, createdType, amount)
		balance = getBalance(t, stub, popcodes.popcode1)
	}

	prevCounter := balance.Counter
	prevOwners := make([]*keyInfo, 1)
	/*
		set owners equal to user1 appended to value stored in newOwners pointer
	*/
	owners := append(*newOwners, users.user1)
	data := "data"
	threshold := len(owners)
	possess(t, stub, popcodes.popcode1, prevOwners, owners, output, data, threshold)
	balance = getBalance(t, stub, popcodes.popcode1)
	if prevCounter == balance.Counter {
		HandleError(t, fmt.Errorf("counter of address (%s) did not change after call to possess. Counter: (%s)",
			balance.Address, balance.Counter))
	}
	if len(balance.Outputs[output].Owners) != len(owners) {
		HandleError(t, fmt.Errorf("after possess on unowned popcode with address: (%s)\n"+
			"number of owners got (%d). Want (%d)\noutputs: (%v)",
			balance.Address, len(balance.Outputs[output].Owners), len(owners), balance.Outputs))
	}
	for i, owner := range owners {
		if balance.Outputs[output].Owners[i] != owner.pubKeyStr {
			HandleError(t, fmt.Errorf("incorrect owner at index (%d). Got (%s). Want (%s)\n",
				i, balance.Outputs[output].Owners[i], owner.pubKeyStr))
		}
	}

	/*
		possess an owned popcode
		multiple new owners
		check counterseed change, number of owners, owner change
		TODO check threshold functionality
	*/
	prevCounter = balance.Counter
	prevOwners[0] = owners[0]
	owners = []*keyInfo{users.user1, users.user2, users.user3, users.user4, users.user5, users.user6}
	fmt.Printf("\n\n\nprevOwners: (%v)\nowners: (%v)\n\n\n\n", prevOwners[0], owners[0])
	data = "data"
	output = 0
	threshold = len(owners)
	possess(t, stub, popcodes.popcode1, prevOwners, owners, output, data, threshold)
	balance = getBalance(t, stub, popcodes.popcode1)
	if prevCounter == balance.Counter {
		HandleError(t, fmt.Errorf("counter of address (%s) did not change after call to possess. Counter: (%s)",
			balance.Address, balance.Counter))
	}
	if len(balance.Outputs[output].Owners) != len(owners) {
		HandleError(t, fmt.Errorf("after possess on unowned popcode with address: (%s)\n"+
			"number of owners got (%d). Want (%d)\noutputs: (%v)",
			balance.Address, len(balance.Outputs[output].Owners), len(owners), balance.Outputs))
	}
	for i, owner := range owners {
		if balance.Outputs[output].Owners[i] != owner.pubKeyStr {
			HandleError(t, fmt.Errorf("incorrect owner at index (%d). Got (%s). Want (%s)\n",
				i, balance.Outputs[output].Owners[i], owner.pubKeyStr))
		}
	}

	/*
		possess and change threshold to 1
		check threshold change
	*/
	prevCounter = balance.Counter
	prevOwners = owners
	owners = []*keyInfo{users.user1, users.user2}
	data = "data"
	output = 0
	threshold = 1
	possess(t, stub, popcodes.popcode1, prevOwners, owners, output, data, threshold)
	balance = getBalance(t, stub, popcodes.popcode1)
	if prevCounter == balance.Counter {
		HandleError(t, fmt.Errorf("counter of address (%s) did not change after call to possess. Counter: (%s)",
			balance.Address, balance.Counter))
	}
	if len(balance.Outputs[output].Owners) != len(owners) {
		HandleError(t, fmt.Errorf("after possess on unowned popcode with address: (%s)\n"+
			"number of owners got (%d). Want (%d)\noutputs: (%v)",
			balance.Address, len(balance.Outputs[output].Owners), len(owners), balance.Outputs))
	}
	for i, owner := range owners {
		if balance.Outputs[output].Owners[i] != owner.pubKeyStr {
			HandleError(t, fmt.Errorf("incorrect owner at index (%d). Got (%s). Want (%s)\n",
				i, balance.Outputs[output].Owners[i], owner.pubKeyStr))
		}
	}
	if balance.Outputs[output].Threshold != int64(threshold) {
		HandleError(t, fmt.Errorf("threshold did not change as expected\nGot (%d)\nWant (%d)", balance.Outputs[output].Threshold, threshold))
	}
	fmt.Printf("\n\nNew BALANCE: (%v)\n\n\n", balance)

	/*
		check threshold functionality
		possess using only one of two owner sigs
	*/
	prevCounter = balance.Counter
	prevOwners = []*keyInfo{users.user1}
	owners[0] = users.user2
	owners[1] = users.user3
	fmt.Printf("\n\n\nprevOwners: (%v)\nowners: (%v)\n\n\n\n", prevOwners[0], owners[0])
	data = "data"
	output = 0
	threshold = len(owners)
	possess(t, stub, popcodes.popcode1, prevOwners, owners, output, data, threshold)
	balance = getBalance(t, stub, popcodes.popcode1)
	if prevCounter == balance.Counter {
		HandleError(t, fmt.Errorf("counter of address (%s) did not change after call to possess. Counter: (%s)",
			balance.Address, balance.Counter))
	}
	if len(balance.Outputs[output].Owners) != len(owners) {
		HandleError(t, fmt.Errorf("after possess on unowned popcode with address: (%s)\n"+
			"number of owners got (%d). Want (%d)\noutputs: (%v)",
			balance.Address, len(balance.Outputs[output].Owners), len(owners), balance.Outputs))
	}
	for i, owner := range owners {
		if balance.Outputs[output].Owners[i] != owner.pubKeyStr {
			HandleError(t, fmt.Errorf("incorrect owner at index (%d). Got (%s). Want (%s)\n",
				i, balance.Outputs[output].Owners[i], owner.pubKeyStr))
		}
	}

	/*
		assign value stored at newOwners pointer equal to owners so that value of newOwners is updated in TestPopcodeChaincode
	*/
	*newOwners = owners
}

func generatePossessSig(t *testing.T, CounterSeedStr string, outputIdx int,
	threshold int32, data string, newOwnersHex string, privateKeyStr string) string {

	privKeyBytes, _ := hex.DecodeString(privateKeyStr)

	privKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), privKeyBytes)

	message := CounterSeedStr + ":" + strconv.FormatInt(int64(outputIdx), 10)
	if threshold > 0 {
		message += ":" + strconv.FormatInt(int64(threshold), 10)
	}
	message += ":" + data

	newOwnersStrings := strings.Split(newOwnersHex, ",")
	for _, owner := range newOwnersStrings {
		message += ":"
		message += owner
	}
	fmt.Printf("\n\n\nSigned POSSESS message %s \n\n\n", message)
	mDigest := sha256.Sum256([]byte(message))
	sig, _ := privKey.Sign(mDigest[:])
	return hex.EncodeToString(sig.Serialize())
}

func hardCodedPossess(t *testing.T, stub *shim.MockStub, counterSeed string, idx int) {
	transferArgs := TuxedoPopsTX.TransferOwners{}
	transferArgs.Address = "74ded2036e988fc56e3cff77a40c58239591e921"
	transferArgs.Data = "Test possess"
	transferArgs.PopcodePubKey, _ = hex.DecodeString("02ca4a8c7dc5090f924cde2264af240d76f6d58a5d2d15c8c5f59d95c70bd9e4dc")
	ownerBytes, _ := hex.DecodeString("0278b76afbefb1e1185bc63ed1a17dd88634e0587491f03e9a8d2d25d9ab289ee7")
	transferArgs.Owners = [][]byte{ownerBytes}
	transferArgs.Output = int32(idx)
	transferArgs.Threshold = 0
	ownerHex := hex.EncodeToString(ownerBytes)

	hexPossessSig := generatePossessSig(t, counterSeed, idx, transferArgs.Threshold, "Test possess",
		ownerHex, "94d7fe7308a452fdf019a0424d9c48ba9b66bdbca565c6fa3b1bf9c646ebac20")

	var err error
	transferArgs.PopcodeSig, err = hex.DecodeString(hexPossessSig)
	transferArgsBytes, _ := proto.Marshal(&transferArgs)
	transferArgsBytesStr := hex.EncodeToString(transferArgsBytes)

	_, err = stub.MockInvoke("4", "transfer", []string{transferArgsBytesStr})
	if err != nil {
		HandleError(t, err)
		t.FailNow()
	}
}

func possess(t *testing.T, stub *shim.MockStub, popcode *keyInfo,
	prevOwners []*keyInfo, newOwners []*keyInfo, idx int, data string, threshold int) {

	transferArgs := TuxedoPopsTX.TransferOwners{}
	transferArgs.Address = popcode.address
	transferArgs.Data = data
	transferArgs.PopcodePubKey, _ = hex.DecodeString(popcode.pubKeyStr)
	transferArgs.Owners = [][]byte{}
	transferArgs.Threshold = int32(threshold)
	for _, owner := range newOwners {
		ownerBytes, err := hex.DecodeString(owner.pubKeyStr)
		if err != nil {
			HandleError(t, fmt.Errorf("error decoding public key string (%s) for user address (%s)\n",
				owner.pubKeyStr, owner.address))
			t.FailNow()
		}
		transferArgs.Owners = append(transferArgs.Owners, ownerBytes)
	}
	var err error
	popcode.counter, err = getCounter(stub, popcode)
	if err != nil {
		HandleError(t, fmt.Errorf("error getting counter in possess: (%v)\n", err.Error()))
		t.FailNow()
	}
	newOwnersSlice := []string{}
	for _, owner := range transferArgs.Owners {
		newOwnersSlice = append(newOwnersSlice, hex.EncodeToString(owner))
	}
	newOwnersString := strings.Join(newOwnersSlice, ",")
	transferArgs.PrevOwnerSigs = make([][]byte, len(prevOwners))
	for i, owner := range prevOwners {
		if owner != nil {
			hexPrevOwnerSig := generatePossessSig(t, popcode.counter, idx,
				transferArgs.Threshold, data, newOwnersString, owner.privKeyStr)

			transferArgs.PrevOwnerSigs[i], err = hex.DecodeString(hexPrevOwnerSig)
			if err != nil {
				HandleError(t, fmt.Errorf("error decoding hexPrevOwnerSig:\ni=(%d)\nowner = (%v)\nerr: (%v)\n",
					i, owner, err.Error()))
				t.FailNow()
			}

		}
	}
	transferArgs.Output = int32(idx)
	hexPossessSig := generatePossessSig(t, popcode.counter, idx, transferArgs.Threshold, data, newOwnersString, popcode.privKeyStr)
	transferArgs.PopcodeSig, err = hex.DecodeString(hexPossessSig)
	transferArgsBytes, _ := proto.Marshal(&transferArgs)
	transferArgsBytesStr := hex.EncodeToString(transferArgsBytes)

	_, err = stub.MockInvoke("4", "transfer", []string{transferArgsBytesStr})
	if err != nil {
		HandleError(t, fmt.Errorf("POSSESS ERROR: (%v)", err.Error()))
		t.FailNow()
	}
}
