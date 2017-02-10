package main

import (
	"fmt"
	"testing"

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

func TestPopcodeChaincode(t *testing.T) {
	bst := new(popcodesChaincode)
	stub := shim.NewMockStub("popcodes", bst)
	checkInit(t, stub, []string{"Hello World"})
	checkQuery(t, stub, "balance", `{"Address":"balance","Counter":"pZGm1Av0IEBKARczz7exkNYsZb8LzaMrV7J32a2fFG4=","Outputs":null}`)
	// checkInvoke(t, stub, []string{`{"uuid":"1234","title":"test"}`})
	// checkQuery(t, stub, "1234", `{"uuid":"1234","title":"test"}`)
}
