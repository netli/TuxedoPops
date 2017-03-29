package main

import (
	"encoding/json"
	"fmt"
	"regexp"
	"runtime"
	"testing"

	"github.com/skuchain/TuxedoPops/TuxedoPopsTX"

	"github.com/hyperledger/fabric/core/chaincode/shim"
)

// Notes fromessage Testing popcode
// Public Key: 02ca4a8c7dc5090f924cde2264af240d76f6d58a5d2d15c8c5f59d95c70bd9e4dc
// Private Key: 94d7fe7308a452fdf019a0424d9c48ba9b66bdbca565c6fa3b1bf9c646ebac20
// Hyperledger address hex 74ded2036e988fc56e3cff77a40c58239591e921
// Hyperledger address Base58: 8sDMfw2Ti7YumfTkbf7RHMgSSSxuAmMFd2GS9wnjkUoX

// Notes fromessage Testing popcode2
// Public Key: 02cb6d65b04c4b84502015f918fe549e95cad4f3b899359a170d4d7d438363c0ce
// Private Key: 60977f22a920c9aa18d58d12cb5e90594152d7aa724bcce21484dfd0f4490b58
// Hyperledger address hex 10734390011641497f489cb475743b8e50d429bb
// Hyperledger address Base58: EHxhLN3Ft4p9jPkR31MJMEMee9G

//Owner1 key
// Public Key: 0278b76afbefb1e1185bc63ed1a17dd88634e0587491f03e9a8d2d25d9ab289ee7
// Private Key: 7142c92e6eba38de08980eeb55b8c98bb19f8d417795adb56b6c4d25da6b26c5

// Owner2 key
// Public Key: 02e138b25db2e74c54f8ca1a5cf79e2d1ed6af5bd1904646e7dc08b6d7b0d12bfd
// Private Key: b18b7d3082b3ff9438a7bf9f5f019f8a52fb64647ea879548b3ca7b551eefd65

func TestPopcodeChaincode(t *testing.T) {
	bst := new(tuxedoPopsChaincode)
	stub := shim.NewMockStub("tuxedoPops", bst)
	checkInit(t, stub, []string{"Hello World"})

	users, err := generateUsers(stub)
	if err != nil {
		HandleError(t, fmt.Errorf("error generating users: (%v)\n", err.Error()))
		t.FailNow()
	}

	popcodes, err := generatePopcodes(stub)
	if err != nil {
		HandleError(t, fmt.Errorf("error generating popcodes: (%v)\n", err.Error()))
		t.FailNow()
	}

	/*
		counterseed values in hardCodedTests, as well as all other parameters, are hardcoded
		As such, these tests must be performed on a fresh chaincode (they must be performed first)
		otherwise, the counterseeds will not match expected values
	*/
	for i := 0; i < 2; i++ {
		checkCounterSeedChange(t, stub)
	}

	testMint(t, stub, popcodes, users)

	/*
		newOwners passed by reference in order to ensure that testUnitize will receive an updated list of current owners
	*/
	newOwners := make([]*keyInfo, 0)
	testPossess(t, stub, popcodes, users, &newOwners)

	fmt.Printf("\n\nnewowners after possess:\n%v\n\n\n\n", newOwners)
	owners := newOwners
	testUnitize(t, stub, popcodes, users, owners)

	/*
		RECIPE
	*/
	ingredients := []*TuxedoPopsTX.Ingredient{}
	ingredient := new(TuxedoPopsTX.Ingredient)
	ingredient.Denominator = 1
	ingredient.Numerator = 1
	ingredient.Type = "Water"
	ingredients = append(ingredients, ingredient)
	recipeName := "Water Vapor Recipe"
	createdType := "Water Vapor"
	recipe(t, stub, recipeName, createdType, users.user1, ingredients)

	testCombine(t, stub, popcodes, users, recipeName, owners)
}

func TestHardCoded(t *testing.T) {
	bst := new(tuxedoPopsChaincode)
	stub := shim.NewMockStub("tuxedoPops", bst)
	checkInit(t, stub, []string{"Hello World"})
	checkQuery(t, stub, "74ded2036e988fc56e3cff77a40c58239591e921", `{"Address":"74ded2036e988fc56e3cff77a40c58239591e921","Counter":"af5eef44907ccdcc33051d035f32f42de0d093fac2fd9d15923448f6af46bc43","Outputs":null}`)
	hardCodedMint(t, stub, "af5eef44907ccdcc33051d035f32f42de0d093fac2fd9d15923448f6af46bc43")
	checkQuery(t, stub, "74ded2036e988fc56e3cff77a40c58239591e921", `{"Address":"74ded2036e988fc56e3cff77a40c58239591e921","Counter":"1adb7c0c1b464fb45860355bf8e711312c608d01202197e58116a424f74af254","Outputs":["{\"Owners\":null,\"Threshold\":0,\"Data\":\"Test Data\",\"Type\":\"Test Asset\",\"PrevCounter\":\"e91d1eab53d597e8e18bb9ebbbaec66d08187d7e14a4a58c8782610ce7c7a74b\",\"Creator\":\"03cc7d40833fdf46e05a7f86a6c9cf8a697a129fbae0676ad6bad71f163ea22b26\",\"Amount\":10}"]}`)
	hardCodedMint(t, stub, "1adb7c0c1b464fb45860355bf8e711312c608d01202197e58116a424f74af254")
	checkQuery(t, stub, "74ded2036e988fc56e3cff77a40c58239591e921", `{"Address":"74ded2036e988fc56e3cff77a40c58239591e921","Counter":"afab4e267a433fe306d1da4608629ce9a280bde98f7004ff883383d65b9f5948","Outputs":["{\"Owners\":null,\"Threshold\":0,\"Data\":\"Test Data\",\"Type\":\"Test Asset\",\"PrevCounter\":\"e91d1eab53d597e8e18bb9ebbbaec66d08187d7e14a4a58c8782610ce7c7a74b\",\"Creator\":\"03cc7d40833fdf46e05a7f86a6c9cf8a697a129fbae0676ad6bad71f163ea22b26\",\"Amount\":10}","{\"Owners\":null,\"Threshold\":0,\"Data\":\"Test Data\",\"Type\":\"Test Asset\",\"PrevCounter\":\"d3e41e748a7094cc520319623479f97dfb6aae0ea915940b72926384fe8d0e8c\",\"Creator\":\"03cc7d40833fdf46e05a7f86a6c9cf8a697a129fbae0676ad6bad71f163ea22b26\",\"Amount\":10}"]}`)
	hardCodedPossess(t, stub, "afab4e267a433fe306d1da4608629ce9a280bde98f7004ff883383d65b9f5948", 1)
	checkQuery(t, stub, "74ded2036e988fc56e3cff77a40c58239591e921", `{"Address":"74ded2036e988fc56e3cff77a40c58239591e921","Counter":"92c7dff498fbe29d4b8d959a0f519a26ce43844f8871736191e5b62f8f507ea0","Outputs":["{\"Owners\":null,\"Threshold\":0,\"Data\":\"Test Data\",\"Type\":\"Test Asset\",\"PrevCounter\":\"e91d1eab53d597e8e18bb9ebbbaec66d08187d7e14a4a58c8782610ce7c7a74b\",\"Creator\":\"03cc7d40833fdf46e05a7f86a6c9cf8a697a129fbae0676ad6bad71f163ea22b26\",\"Amount\":10}","{\"Owners\":[\"0278b76afbefb1e1185bc63ed1a17dd88634e0587491f03e9a8d2d25d9ab289ee7\"],\"Threshold\":1,\"Data\":\"Test possess\",\"Type\":\"Test Asset\",\"PrevCounter\":\"afab4e267a433fe306d1da4608629ce9a280bde98f7004ff883383d65b9f5948\",\"Creator\":\"03cc7d40833fdf46e05a7f86a6c9cf8a697a129fbae0676ad6bad71f163ea22b26\",\"Amount\":10}"]}`)
	hardCodedUnitize(t, stub, "92c7dff498fbe29d4b8d959a0f519a26ce43844f8871736191e5b62f8f507ea0")
	checkQuery(t, stub, "74ded2036e988fc56e3cff77a40c58239591e921", `{"Address":"74ded2036e988fc56e3cff77a40c58239591e921","Counter":"92c7dff498fbe29d4b8d959a0f519a26ce43844f8871736191e5b62f8f507ea0","Outputs":["{\"Owners\":[\"0278b76afbefb1e1185bc63ed1a17dd88634e0587491f03e9a8d2d25d9ab289ee7\"],\"Threshold\":1,\"Data\":\"Test possess\",\"Type\":\"Test Asset\",\"PrevCounter\":\"afab4e267a433fe306d1da4608629ce9a280bde98f7004ff883383d65b9f5948\",\"Creator\":\"03cc7d40833fdf46e05a7f86a6c9cf8a697a129fbae0676ad6bad71f163ea22b26\",\"Amount\":10}"]}`)
	checkQuery(t, stub, "10734390011641497f489cb475743b8e50d429bb", `{"Address":"10734390011641497f489cb475743b8e50d429bb","Counter":"3d2cc9f7d475cf79347ff317b1164daa50ced56d3ee977252da0430f39fa7a4e","Outputs":["{\"Owners\":null,\"Threshold\":0,\"Data\":\"Test Unitize\",\"Type\":\"Test Asset\",\"PrevCounter\":\"660bfdba4544847711d515fb26c5f1f62f0c9fc45b5a41b0fefcc1d58de4f1c0\",\"Creator\":\"03cc7d40833fdf46e05a7f86a6c9cf8a697a129fbae0676ad6bad71f163ea22b26\",\"Amount\":10}"]}`)
	hardCodedCombine(t, stub)
}

func checkInit(t *testing.T, stub *shim.MockStub, args []string) {
	_, err := stub.MockInit("1", "", args)
	if err != nil {
		HandleError(t, fmt.Errorf("INIT", args, "failed", err))
		t.FailNow()
	}
}

func checkInvoke(t *testing.T, stub *shim.MockStub, args []string) {
	_, err := stub.MockInvoke("1", "invoke", args)
	if err != nil {
		HandleError(t, fmt.Errorf("invoke", args, "failed", err))
		t.FailNow()
	}
}

func checkQuery(t *testing.T, stub *shim.MockStub, name string, value string) {
	bytes, err := stub.MockQuery("balance", []string{name})

	if err != nil {
		HandleError(t, fmt.Errorf("Query for address (", name, ") failed", err))
		t.FailNow()
	}
	if bytes == nil {
		HandleError(t, fmt.Errorf("Query for address (", name, ") failed to get value"))
		t.FailNow()
	}
	if string(bytes) != value {
		HandleError(t, fmt.Errorf("Query value for address (%s) wanted:\n(%s)\n\nGot:\n(%s)\n", name, value, string(bytes)))
		t.FailNow()
	}
}

func getCounter(stub *shim.MockStub, keys *keyInfo) (string, error) {
	//query balance to get counterSeed
	bytes, err := stub.MockQuery("balance", []string{keys.address})
	if err != nil {
		return "", fmt.Errorf("balance query failure on address: (%s)\n", keys.address)
	}
	var balanceResult map[string]interface{}
	json.Unmarshal(bytes, &balanceResult)
	return balanceResult["Counter"].(string), nil
}

type balanceJSON struct {
	Address string
	Counter string
	Outputs []string
}

type finalBalanceJSON struct {
	Address string
	Counter string
	Outputs []outputJSON
}

type outputJSON struct {
	Owners      []string `json:"Owners"`
	Threshold   int64    `json:"Threshold"`
	Amount      int64    `json:"Amount"`
	Type        string   `json:"Type"`
	Data        string   `json:"Data"`
	Recipe      string   `json:"Recipe"`
	Creator     string   `json:"Creator"`
	PrevCounter string   `json:"PrevCounter"`
}

func getBalance(t *testing.T, stub *shim.MockStub, keys *keyInfo) finalBalanceJSON {
	balance := balanceJSON{}
	bytes, err := stub.MockQuery("balance", []string{keys.address})
	if err != nil {
		HandleError(t, fmt.Errorf("balance query failure on address: (%s)\n", keys.address))
	}

	err = json.Unmarshal(bytes, &balance)
	if err != nil {
		HandleError(t, fmt.Errorf("error unmarshalling balance for address :(%s)", keys.address))
		t.FailNow()
	}
	balanceResult := finalBalanceJSON{}
	balanceResult.Address = balance.Address
	balanceResult.Counter = balance.Counter
	for _, output := range balance.Outputs {
		var result outputJSON
		if err := json.Unmarshal([]byte(output), &result); err != nil {
			HandleError(t, fmt.Errorf("Error unmarshalling balance output (%v) into outputJSON struct\nERR: (%s)",
				output, err.Error()))
		}
		balanceResult.Outputs = append(balanceResult.Outputs, result)
	}
	return balanceResult
}

type keyInfo struct {
	privKeyStr string
	pubKeyStr  string
	address    string
	counter    string
}

type users struct {
	user1 *keyInfo
	user2 *keyInfo
	user3 *keyInfo
	user4 *keyInfo
	user5 *keyInfo
	user6 *keyInfo
	user7 *keyInfo
}

func generateUsers(stub *shim.MockStub) (*users, error) {
	users := new(users)
	var err error
	users.user1, err = generateKeys()
	if err != nil {
		return nil, fmt.Errorf("error generating keys in generateUsers: (%v)\n", err.Error())
	}
	users.user1.counter, err = getCounter(stub, users.user1)
	if err != nil {
		return nil, fmt.Errorf("error generating counterSeed in generateUsers: (%v)\n", err.Error())
	}

	users.user2, err = generateKeys()
	if err != nil {
		return nil, fmt.Errorf("error generating keys in generateUsers: (%v)\n", err.Error())
	}
	users.user2.counter, err = getCounter(stub, users.user2)
	if err != nil {
		return nil, fmt.Errorf("error generating counterSeed in generateUsers: (%v)\n", err.Error())
	}

	users.user3, err = generateKeys()
	if err != nil {
		return nil, fmt.Errorf("error generating keys in generateUsers: (%v)\n", err.Error())
	}
	users.user3.counter, err = getCounter(stub, users.user3)
	if err != nil {
		return nil, fmt.Errorf("error generating counterSeed in generateUsers: (%v)\n", err.Error())
	}

	users.user4, err = generateKeys()
	if err != nil {
		return nil, fmt.Errorf("error generating keys in generateUsers: (%v)\n", err.Error())
	}
	users.user4.counter, err = getCounter(stub, users.user4)
	if err != nil {
		return nil, fmt.Errorf("error generating counterSeed in generateUsers: (%v)\n", err.Error())
	}

	users.user5, err = generateKeys()
	if err != nil {
		return nil, fmt.Errorf("error generating keys in generateUsers: (%v)\n", err.Error())
	}
	users.user5.counter, err = getCounter(stub, users.user5)
	if err != nil {
		return nil, fmt.Errorf("error generating counterSeed in generateUsers: (%v)\n", err.Error())
	}

	users.user6, err = generateKeys()
	if err != nil {
		return nil, fmt.Errorf("error generating keys in generateUsers: (%v)\n", err.Error())
	}
	users.user6.counter, err = getCounter(stub, users.user6)
	if err != nil {
		return nil, fmt.Errorf("error generating counterSeed in generateUsers: (%v)\n", err.Error())
	}

	users.user7, err = generateKeys()
	if err != nil {
		return nil, fmt.Errorf("error generating keys in generateUsers: (%v)\n", err.Error())
	}
	users.user7.counter, err = getCounter(stub, users.user7)
	if err != nil {
		return nil, fmt.Errorf("error generating counterSeed in generateUsers: (%v)\n", err.Error())
	}

	return users, nil
}

type popcodes struct {
	popcode1 *keyInfo
	popcode2 *keyInfo
	popcode3 *keyInfo
	popcode4 *keyInfo
	popcode5 *keyInfo
	popcode6 *keyInfo
	popcode7 *keyInfo
}

func generatePopcodes(stub *shim.MockStub) (*popcodes, error) {
	popcodes := new(popcodes)
	var err error
	popcodes.popcode1, err = generateKeys()
	if err != nil {
		return nil, fmt.Errorf("error generating keys in generatePopcodes: (%v)\n", err.Error())
	}
	popcodes.popcode1.counter, err = getCounter(stub, popcodes.popcode1)
	if err != nil {
		return nil, fmt.Errorf("error generating counterSeed in generateUsers: (%v)\n", err.Error())
	}

	popcodes.popcode2, err = generateKeys()
	if err != nil {
		return nil, fmt.Errorf("error generating keys in generatePopcodes: (%v)\n", err.Error())
	}
	popcodes.popcode2.counter, err = getCounter(stub, popcodes.popcode2)
	if err != nil {
		return nil, fmt.Errorf("error generating counterSeed in generateUsers: (%v)\n", err.Error())
	}

	popcodes.popcode3, err = generateKeys()
	if err != nil {
		return nil, fmt.Errorf("error generating keys in generatePopcodes: (%v)\n", err.Error())
	}
	popcodes.popcode3.counter, err = getCounter(stub, popcodes.popcode3)
	if err != nil {
		return nil, fmt.Errorf("error generating counterSeed in generateUsers: (%v)\n", err.Error())
	}

	popcodes.popcode4, err = generateKeys()
	if err != nil {
		return nil, fmt.Errorf("error generating keys in generatePopcodes: (%v)\n", err.Error())
	}
	popcodes.popcode4.counter, err = getCounter(stub, popcodes.popcode4)
	if err != nil {
		return nil, fmt.Errorf("error generating counterSeed in generateUsers: (%v)\n", err.Error())
	}

	popcodes.popcode5, err = generateKeys()
	if err != nil {
		return nil, fmt.Errorf("error generating keys in generatePopcodes: (%v)\n", err.Error())
	}
	popcodes.popcode5.counter, err = getCounter(stub, popcodes.popcode5)
	if err != nil {
		return nil, fmt.Errorf("error generating counterSeed in generateUsers: (%v)\n", err.Error())
	}

	popcodes.popcode6, err = generateKeys()
	if err != nil {
		return nil, fmt.Errorf("error generating keys in generatePopcodes: (%v)\n", err.Error())
	}
	popcodes.popcode6.counter, err = getCounter(stub, popcodes.popcode6)
	if err != nil {
		return nil, fmt.Errorf("error generating counterSeed in generateUsers: (%v)\n", err.Error())
	}

	popcodes.popcode7, err = generateKeys()
	if err != nil {
		return nil, fmt.Errorf("error generating keys in generatePopcodes: (%v)\n", err.Error())
	}
	popcodes.popcode7.counter, err = getCounter(stub, popcodes.popcode7)
	if err != nil {
		return nil, fmt.Errorf("error generating counterSeed in generateUsers: (%v)\n", err.Error())
	}

	return popcodes, nil
}

func HandleError(t *testing.T, err error) (b bool) {
	if err != nil {
		_, fn, line, _ := runtime.Caller(1)
		re := regexp.MustCompile("[^/]+$")
		t.Errorf("\x1b[32m\n[ERROR] in %s\tat line: %d\n%v\x1b[0m\n\n", re.FindAllString(fn, -1)[0], line, err)
		b = true
	}
	return
}
