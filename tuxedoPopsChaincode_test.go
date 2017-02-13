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

// Notes from Testing popcode
// Public Key: 02ca4a8c7dc5090f924cde2264af240d76f6d58a5d2d15c8c5f59d95c70bd9e4dc
// Private Key: 94d7fe7308a452fdf019a0424d9c48ba9b66bdbca565c6fa3b1bf9c646ebac20
// Hyperledger address hex 74ded2036e988fc56e3cff77a40c58239591e921c442867d03bcea6a5eb8ac4e
// Hyperledger address Base58: 8sDMfw2Ti7YumfTkbf7RHMgSSSxuAmMFd2GS9wnjkUoX
func checkInit(t *testing.T, stub *shim.MockStub, args []string) {
	_, err := stub.MockInit("1", "", args)
	if err != nil {
		fmt.Println("INIT", args, "failed", err)
		t.FailNow()
	}
}

func checkInvoke(t *testing.T, stub *shim.MockStub, args []string) {
	_, err := stub.MockInvoke("1", "UPSERT", args)
	if err != nil {
		fmt.Println("UPSERT", args, "failed", err)
		t.FailNow()
	}
}

func checkQuery(t *testing.T, stub *shim.MockStub, name string, value string) {
	bytes, err := stub.MockQuery("balance", []string{name})

	if err != nil {
		fmt.Println("Query", name, "failed", err)
		t.FailNow()
	}
	if bytes == nil {
		fmt.Println("Query", name, "failed to get value")
		t.FailNow()
	}
	if string(bytes) != value {
		fmt.Println("Query value", name, "was not", value, "as expected instead", string(bytes))
		t.FailNow()
	}
}

func mint(t *testing.T, stub *shim.MockStub, counterSeed string) {
	createArgs := TuxedoPopsTX.CreateTX{}
	createArgs.Address = "74ded2036e988fc56e3cff77a40c58239591e921c442867d03bcea6a5eb8ac4e"
	createArgs.Amount = 10
	pubKeyBytes, err := hex.DecodeString("03cc7d40833fdf46e05a7f86a6c9cf8a697a129fbae0676ad6bad71f163ea22b26")
	if err != nil {
		fmt.Println(err)

	}
	createArgs.CreatorPubKey = pubKeyBytes
	createArgs.CreatorSig = generateCreateSig(counterSeed, 10, "Test Data", "74ded2036e988fc56e3cff77a40c58239591e921c442867d03bcea6a5eb8ac4e", "7ff1ac3d9dfc56315ee610d0a15609d13c399cf9c92ba2e32e7b1d25ea5c9494")
	createArgs.Data = "Test Data"
	createArgBytes, err := proto.Marshal(&createArgs)
	createArgBytesStr := hex.EncodeToString(createArgBytes)
	_, err = stub.MockInvoke("3", "create", []string{createArgBytesStr})
	if err != nil {
		fmt.Println(err)
	}
}

func possess(t *testing.T, stub *shim.MockStub, counterSeed string) {
	transferArgs := TuxedoPopsTX.TransferOwners{}
	transferArgs.Address = "74ded2036e988fc56e3cff77a40c58239591e921c442867d03bcea6a5eb8ac4e"
}
func generateCreateSig(CounterSeedStr string, amount int, data string, addr string, privateKeyStr string) []byte {
	privKeyByte, _ := hex.DecodeString(privateKeyStr)

	privKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), privKeyByte)

	message := CounterSeedStr + ":" + addr + ":" + strconv.FormatInt(int64(amount), 10) + ":" + data
	messageBytes := sha256.Sum256([]byte(message))
	sig, _ := privKey.Sign(messageBytes[:])

	return sig.Serialize()
}

func TestPopcodeChaincode(t *testing.T) {
	bst := new(tuxedoPopsChaincode)
	stub := shim.NewMockStub("tuxedoPops", bst)
	checkInit(t, stub, []string{"Hello World"})
	checkQuery(t, stub, "74ded2036e988fc56e3cff77a40c58239591e921c442867d03bcea6a5eb8ac4e", `{"Address":"74ded2036e988fc56e3cff77a40c58239591e921c442867d03bcea6a5eb8ac4e","Counter":"15033f2887d704c18539c645cf3b341c30dac35214d9ca829b75761c3c7bfbda","Outputs":null}`)
	mint(t, stub, "15033f2887d704c18539c645cf3b341c30dac35214d9ca829b75761c3c7bfbda")
	checkQuery(t, stub, "74ded2036e988fc56e3cff77a40c58239591e921c442867d03bcea6a5eb8ac4e", `{"Address":"74ded2036e988fc56e3cff77a40c58239591e921c442867d03bcea6a5eb8ac4e","Counter":"db4d33af4f686ef0de2d75f6ec5563f35219a9e60167f1008eb028ac2e61d730","Outputs":["{\"Owners\":null,\"Threshold\":0,\"Data\":\"Test Data\",\"Type\":\"\",\"PrevCounter\":\"15033f2887d704c18539c645cf3b341c30dac35214d9ca829b75761c3c7bfbda\",\"Creator\":\"03cc7d40833fdf46e05a7f86a6c9cf8a697a129fbae0676ad6bad71f163ea22b26\",\"Amount\":10}"]}`)
	mint(t, stub, "db4d33af4f686ef0de2d75f6ec5563f35219a9e60167f1008eb028ac2e61d730")
	checkQuery(t, stub, "74ded2036e988fc56e3cff77a40c58239591e921c442867d03bcea6a5eb8ac4e", `{"Address":"74ded2036e988fc56e3cff77a40c58239591e921c442867d03bcea6a5eb8ac4e","Counter":"7eb2b7c94824f3c07d8581b1e329597553cdebf450cd4289b4d23f951f92fe77","Outputs":["{\"Owners\":null,\"Threshold\":0,\"Data\":\"Test Data\",\"Type\":\"\",\"PrevCounter\":\"15033f2887d704c18539c645cf3b341c30dac35214d9ca829b75761c3c7bfbda\",\"Creator\":\"03cc7d40833fdf46e05a7f86a6c9cf8a697a129fbae0676ad6bad71f163ea22b26\",\"Amount\":10}","{\"Owners\":null,\"Threshold\":0,\"Data\":\"Test Data\",\"Type\":\"\",\"PrevCounter\":\"db4d33af4f686ef0de2d75f6ec5563f35219a9e60167f1008eb028ac2e61d730\",\"Creator\":\"03cc7d40833fdf46e05a7f86a6c9cf8a697a129fbae0676ad6bad71f163ea22b26\",\"Amount\":10}"]}`)

	// checkInvoke(t, stub, []string{`{"uuid":"1234","title":"test"}`})
	// checkQuery(t, stub, "1234", `{"uuid":"1234","title":"test"}`)
}
