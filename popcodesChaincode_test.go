package main

import (
	"crypto/sha256"
	"fmt"
	"strconv"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/skuchain/popcodes_utxo/PopcodesTX"

	"encoding/hex"

	"github.com/btcsuite/btcd/btcec"
	"github.com/hyperledger/fabric/core/chaincode/shim"
)

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
		fmt.Println("Query value", name, "was not", value, "as expected", string(bytes))
		t.FailNow()
	}
}

func checkCreate(t *testing.T, stub *shim.MockStub, counterSeed string) {
	createArgs := popcodesTX.CreateTX{}
	addrBytes, err := hex.DecodeString("66ea3c64e079948d5c01ba3f2eb4697dcdf9976a0804bc849d8fa06bae869d65")
	if err != nil {
		fmt.Println(err)
	}
	createArgs.Address = addrBytes
	createArgs.Amount = 10
	pubKeyBytes, err := hex.DecodeString("03cc7d40833fdf46e05a7f86a6c9cf8a697a129fbae0676ad6bad71f163ea22b26")
	if err != nil {
		fmt.Println(err)

	}
	createArgs.CreatorPubKey = pubKeyBytes
	createArgs.CreatorSig = generateCreateSig(counterSeed, 10, "Test Data", "66ea3c64e079948d5c01ba3f2eb4697dcdf9976a0804bc849d8fa06bae869d65", "7ff1ac3d9dfc56315ee610d0a15609d13c399cf9c92ba2e32e7b1d25ea5c9494")
	createArgs.Data = "Test Data"
	createArgBytes, err := proto.Marshal(&createArgs)
	createArgBytesStr := hex.EncodeToString(createArgBytes)
	_, err = stub.MockInvoke("3", "create", []string{createArgBytesStr})
	if err != nil {
		fmt.Println(err)

	}
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
	bst := new(popcodesChaincode)
	stub := shim.NewMockStub("popcodes", bst)
	checkInit(t, stub, []string{"Hello World"})
	checkQuery(t, stub, "66ea3c64e079948d5c01ba3f2eb4697dcdf9976a0804bc849d8fa06bae869d65", `{"Address":"66ea3c64e079948d5c01ba3f2eb4697dcdf9976a0804bc849d8fa06bae869d65","Counter":"e46f24333bf59eb7da4ab55fa041bc071e7a3fcbbf2b41c947ceac24f195b598","Outputs":null}`)
	checkCreate(t, stub, "e46f24333bf59eb7da4ab55fa041bc071e7a3fcbbf2b41c947ceac24f195b598")
	checkQuery(t, stub, "66ea3c64e079948d5c01ba3f2eb4697dcdf9976a0804bc849d8fa06bae869d65", `{"Address":"66ea3c64e079948d5c01ba3f2eb4697dcdf9976a0804bc849d8fa06bae869d65","Counter":"c1db5aefa87f69f0a80f1578a89db52d0302dfffe0506b73a86e81706f6ffcdc","Outputs":["{\"Owners\":null,\"Threshold\":0,\"Data\":\"Test Data\",\"Creator\":\"03cc7d40833fdf46e05a7f86a6c9cf8a697a129fbae0676ad6bad71f163ea22b26\",\"Amount\":10}"]}`)

	// checkInvoke(t, stub, []string{`{"uuid":"1234","title":"test"}`})
	// checkQuery(t, stub, "1234", `{"uuid":"1234","title":"test"}`)
}
