package main

import (
	"crypto/sha256"
	"fmt"
	"strconv"
	"testing"

	"github.com/golang/protobuf/proto"
	txcache "github.com/skuchain/TuxedoPops/TXCache"
	"github.com/skuchain/TuxedoPops/TuxedoPopsTX"

	"encoding/hex"
	"encoding/json"

	"github.com/btcsuite/btcd/btcec"
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
func checkInit(t *testing.T, stub *shim.MockStub, args []string) {
	_, err := stub.MockInit("1", "", args)
	if err != nil {
		fmt.Println("INIT", args, "failed", err)
		t.FailNow()
	}
}

func checkInvoke(t *testing.T, stub *shim.MockStub, args []string) {
	_, err := stub.MockInvoke("1", "invoke", args)
	if err != nil {
		fmt.Println("invoke", args, "failed", err)
		t.FailNow()
	}
}

func checkQuery(t *testing.T, stub *shim.MockStub, name string, value string) {
	bytes, err := stub.MockQuery("balance", []string{name})

	if err != nil {
		fmt.Println("Query for address (", name, ") failed", err)
		t.FailNow()
	}
	if bytes == nil {
		fmt.Println("Query for address (", name, ") failed to get value")
		t.FailNow()
	}
	if string(bytes) != value {
		fmt.Println("Query value for address (", name, ") was not", value, "as expected instead", string(bytes))
		t.FailNow()
	}
}

func mint(t *testing.T, stub *shim.MockStub, counterSeed string) {
	createArgs := TuxedoPopsTX.CreateTX{}
	createArgs.Address = "74ded2036e988fc56e3cff77a40c58239591e921"
	createArgs.Amount = 10
	pubKeyBytes, err := hex.DecodeString("03cc7d40833fdf46e05a7f86a6c9cf8a697a129fbae0676ad6bad71f163ea22b26")
	if err != nil {
		fmt.Println(err)
	}
	createArgs.CreatorPubKey = pubKeyBytes
	hexCreatorSig := generateCreateSig(counterSeed, 10, "Test Asset", "Test Data", "74ded2036e988fc56e3cff77a40c58239591e921", "7ff1ac3d9dfc56315ee610d0a15609d13c399cf9c92ba2e32e7b1d25ea5c9494")

	createArgs.CreatorSig, err = hex.DecodeString(hexCreatorSig)
	if err != nil {
		fmt.Println(err)
	}
	createArgs.Data = "Test Data"
	createArgs.Type = "Test Asset"
	createArgBytes, err := proto.Marshal(&createArgs)
	createArgBytesStr := hex.EncodeToString(createArgBytes)
	_, err = stub.MockInvoke("3", "create", []string{createArgBytesStr})
	if err != nil {
		fmt.Println(err)
	}
}

//altMint takes in a key struct which holds input of private key, public key, and address
func altMint(t *testing.T, stub *shim.MockStub, keys *keyInfo, counterSeed string) {
	createArgs := TuxedoPopsTX.CreateTX{}
	createArgs.Address = keys.address
	createArgs.Amount = 10
	createArgs.Data = "Test Data"
	createArgs.Type = "Test Asset"

	pubKeyBytes, err := hex.DecodeString(keys.pubKeyStr)
	if err != nil {
		fmt.Println(err)
	}
	createArgs.CreatorPubKey = pubKeyBytes
	hexCreatorSig := generateCreateSig(counterSeed, 10, "Test Asset", "Test Data", keys.address, keys.privKeyStr)

	createArgs.CreatorSig, err = hex.DecodeString(hexCreatorSig)
	if err != nil {
		fmt.Println(err)
	}

	createArgBytes, err := proto.Marshal(&createArgs)
	createArgBytesStr := hex.EncodeToString(createArgBytes)
	_, err = stub.MockInvoke("3", "create", []string{createArgBytesStr})
	if err != nil {
		fmt.Println(err)
	}
}

func generateCombineSig(counter string, combine TuxedoPopsTX.Combine, amount int, data string, privateKeyStr string) string {
	privKeyByte, _ := hex.DecodeString(privateKeyStr)

	privKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), privKeyByte)

	message := counter
	message += ":" + combine.Recipe
	for _, source := range combine.GetSources() {
		message += ":" + strconv.FormatInt(int64(source.Idx()), 10)
		message += ":" + strconv.FormatInt(int64(source.Amount()), 10)
	}
	message += ":" + strconv.FormatInt(int64(amount), 10) + ":" + data

	fmt.Printf("\n\ncombine message: (%s)\n\n", message)
	messageBytes := sha256.Sum256([]byte(message))
	fmt.Println(message)

	sig, _ := privKey.Sign(messageBytes[:])

	return hex.EncodeToString(sig.Serialize())
}

func generateRecipeSig(recipeName string, createdType string,
	ingredients []*TuxedoPopsTX.Ingredient, privateKeyStr string) string {

	privKeyByte, _ := hex.DecodeString(privateKeyStr)

	privKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), privKeyByte)

	message := recipeName + ":" + createdType
	for _, ingredient := range ingredients {
		message += ":" + strconv.FormatInt(int64(ingredient.Numerator), 10) + ":" +
			strconv.FormatInt(int64(ingredient.Denominator), 10) + ":" + ingredient.Type
	}
	fmt.Printf("Signed Message: (%s)\n\n\n", message)
	messageBytes := sha256.Sum256([]byte(message))
	sig, _ := privKey.Sign(messageBytes[:])
	return hex.EncodeToString(sig.Serialize())
}

func registerRecipe(t *testing.T, stub *shim.MockStub) {
	recipeArgs := TuxedoPopsTX.Recipe{}
	recipeArgs.RecipeName = "test recipe"
	recipeArgs.CreatedType = "B"
	recipeArgs.CreatorPubKey, _ = hex.DecodeString("02ca4a8c7dc5090f924cde2264af240d76f6d58a5d2d15c8c5f59d95c70bd9e4dc")
	test := make([]*TuxedoPopsTX.Ingredient, 1)
	test[0] = new(TuxedoPopsTX.Ingredient)
	test[0].Denominator = 1
	test[0].Numerator = 1
	test[0].Type = "Test Asset"

	recipeArgs.Ingredients = test

	sigHex := generateRecipeSig(recipeArgs.RecipeName, recipeArgs.CreatedType,
		recipeArgs.Ingredients, "94d7fe7308a452fdf019a0424d9c48ba9b66bdbca565c6fa3b1bf9c646ebac20")

	var err error
	recipeArgs.CreatorSig, err = hex.DecodeString(sigHex)
	if err != nil {
		fmt.Printf("error decoding creator signature in register recipe. ERR: (%v)", err.Error())
		t.FailNow()
	}
	recipeArgsBytes, err := proto.Marshal(&recipeArgs)
	if err != nil {
		fmt.Printf("error marshalling recipeArgs in registerRecipe. ERR: (%s)\n", err.Error())
		t.FailNow()
	}
	recipeArgsBytesStr := hex.EncodeToString(recipeArgsBytes)
	_, err = stub.MockInvoke("4", "recipe", []string{recipeArgsBytesStr})
	if err != nil {
		fmt.Println(err)
		t.Errorf("error invoking recipe: (%v)", err.Error())
	}
}

func generateCreateSig(CounterSeedStr string, amount int, assetType string, data string, addr string, privateKeyStr string) string {
	privKeyByte, _ := hex.DecodeString(privateKeyStr)

	privKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), privKeyByte)

	message := CounterSeedStr + ":" + addr + ":" + strconv.FormatInt(int64(amount), 10) + ":" + assetType + ":" + data
	fmt.Println("Signed Message")
	fmt.Println(message)
	messageBytes := sha256.Sum256([]byte(message))
	sig, _ := privKey.Sign(messageBytes[:])
	return hex.EncodeToString(sig.Serialize())
}

func possess(t *testing.T, stub *shim.MockStub, counterSeed string, idx int) {
	transferArgs := TuxedoPopsTX.TransferOwners{}
	transferArgs.Address = "74ded2036e988fc56e3cff77a40c58239591e921"
	transferArgs.Data = "Test possess"
	transferArgs.PopcodePubKey, _ = hex.DecodeString("02ca4a8c7dc5090f924cde2264af240d76f6d58a5d2d15c8c5f59d95c70bd9e4dc")
	ownerBytes, _ := hex.DecodeString("0278b76afbefb1e1185bc63ed1a17dd88634e0587491f03e9a8d2d25d9ab289ee7")
	transferArgs.Owners = [][]byte{ownerBytes}
	transferArgs.Output = int32(idx)
	ownerHex := hex.EncodeToString(ownerBytes)
	hexPossessSig := generatePossessSig(counterSeed, idx, "Test possess", ownerHex, "94d7fe7308a452fdf019a0424d9c48ba9b66bdbca565c6fa3b1bf9c646ebac20")
	var err error
	transferArgs.PopcodeSig, err = hex.DecodeString(hexPossessSig)
	transferArgsBytes, _ := proto.Marshal(&transferArgs)
	transferArgsBytesStr := hex.EncodeToString(transferArgsBytes)

	_, err = stub.MockInvoke("4", "transfer", []string{transferArgsBytesStr})
	if err != nil {
		fmt.Println(err)
	}
}

func generatePossessSig(CounterSeedStr string, outputIdx int, data string, newOwnersHex string, privateKeyStr string) string {
	privKeyByte, _ := hex.DecodeString(privateKeyStr)

	privKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), privKeyByte)

	message := CounterSeedStr + ":" + strconv.FormatInt(int64(outputIdx), 10) + ":" + data
	newOwnersTmp, err := hex.DecodeString(newOwnersHex)
	if err != nil {
		fmt.Println(err)
	}
	newOwners := [][]byte{newOwnersTmp}

	for _, newO := range newOwners {
		message += ":"
		message += hex.EncodeToString(newO)
	}
	// fmt.Printf("Signed message %s \n", message)
	mDigest := sha256.Sum256([]byte(message))
	sig, _ := privKey.Sign(mDigest[:])
	return hex.EncodeToString(sig.Serialize())
}

// func generatePossessSig(CounterSeedStr string, outputIdx int, data string, newOwners [][]byte, privateKeyStr string) []byte {
// 	privKeyByte, _ := hex.DecodeString(privateKeyStr)

// 	privKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), privKeyByte)

// 	message := CounterSeedStr + ":" + strconv.FormatInt(int64(outputIdx), 10) + ":" + data

// 	for _, newO := range newOwners {
// 		message += ":"
// 		message += hex.EncodeToString(newO)
// 	}
// 	// fmt.Printf("Signed message %s \n", message)
// 	mDigest := sha256.Sum256([]byte(message))
// 	sig, _ := privKey.Sign(mDigest[:])
// 	return sig.Serialize()
// }

func unitize(t *testing.T, stub *shim.MockStub, counterSeed string) {
	unitizeArgs := TuxedoPopsTX.Unitize{}
	unitizeArgs.Data = "Test Unitize"
	unitizeArgs.DestAddress = "10734390011641497f489cb475743b8e50d429bb"
	unitizeArgs.DestAmounts = []int32{10}
	unitizeArgs.SourceAddress = "74ded2036e988fc56e3cff77a40c58239591e921"
	unitizeArgs.SourceOutput = 0
	unitizeArgs.PopcodePubKey, _ = hex.DecodeString("02ca4a8c7dc5090f924cde2264af240d76f6d58a5d2d15c8c5f59d95c70bd9e4dc")
	ownerSig := generateUnitizeSig(counterSeed, unitizeArgs.DestAddress, 0, []int{10}, unitizeArgs.Data, "7142c92e6eba38de08980eeb55b8c98bb19f8d417795adb56b6c4d25da6b26c5")
	unitizeArgs.OwnerSigs = [][]byte{ownerSig}
	unitizeArgs.PopcodeSig = generateUnitizeSig(counterSeed, unitizeArgs.DestAddress, 0, []int{10}, unitizeArgs.Data, "94d7fe7308a452fdf019a0424d9c48ba9b66bdbca565c6fa3b1bf9c646ebac20")
	unitizeArgsBytes, _ := proto.Marshal(&unitizeArgs)
	unitizeArgsBytesStr := hex.EncodeToString(unitizeArgsBytes)

	_, err := stub.MockInvoke("4", "unitize", []string{unitizeArgsBytesStr})
	if err != nil {
		fmt.Println(err)
		t.FailNow()
	}
}

func generateUnitizeSig(CounterSeedStr string, destAddr string, outputIdx int, amounts []int, data string, privateKeyStr string) []byte {
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

func checkCombine(t *testing.T, stub *shim.MockStub) {
	txCache := txcache.TXCache{}
	txCacheBytes, err := stub.GetState("TxCache")
	if err != nil {
		fmt.Println(err)
	}
	proto.Unmarshal(txCacheBytes, &txCache)

	//create a new set of keys
	keys := new(keyInfo)
	keys.privKeyStr, err = newPrivateKeyString()
	if err != nil {
		fmt.Printf("error generating private key: %v", err)
	}
	keys.pubKeyStr, err = newPubKeyString(keys.privKeyStr)
	if err != nil {
		fmt.Printf("error generating public key: %v", err)
	}
	keys.address = newAddress(keys.pubKeyStr)

	//query balance to get counterSeed
	bytes, err := stub.MockQuery("balance", []string{keys.address})
	if err != nil {
		t.Errorf("query failure\n")
	}
	balanceResult := make(map[string]string)
	json.Unmarshal(bytes, &balanceResult)
	fmt.Println("\n\n\nBracket Results")
	fmt.Println(string(bytes))
	counter := balanceResult["Counter"]

	//mint transaction with keys and counterseed
	altMint(t, stub, keys, counter)

	//query balance to get counterSeed
	bytes, err = stub.MockQuery("balance", []string{keys.address})
	if err != nil {
		t.Errorf("query failure\n")
	}
	balanceResult = make(map[string]string)
	json.Unmarshal(bytes, &balanceResult)

	fmt.Println("\n\n\nBracket Results After Mint")
	fmt.Println(string(bytes))
	counter = balanceResult["Counter"]

	registerRecipe(t, stub)

	//perform combination
	combineArgs := TuxedoPopsTX.Combine{}
	combineArgs.Address = keys.address
	//Sources
	combineArgs.Sources = make([]*TuxedoPopsTX.CombineSources, 1)
	combineArgs.Sources[0] = new(TuxedoPopsTX.CombineSources)
	combineArgs.Sources[0].SourceAmount = 10
	combineArgs.Sources[0].SourceOutput = 0

	combineArgs.Amount = 10
	combineArgs.Recipe = "test recipe"
	combineArgs.Data = "test data"

	creatorPrivKey, _ := newPrivateKeyString()
	creatorPubKeyStr, _ := newPubKeyString(creatorPrivKey)

	combineArgs.CreatorPubKey, _ = hex.DecodeString(creatorPubKeyStr)
	if err != nil {
		fmt.Printf("error generating private key: %v", err.Error())
	}

	combineArgs.CreatorSig, err = hex.DecodeString(generateCombineSig(counter, combineArgs, int(combineArgs.Amount), combineArgs.Data, creatorPrivKey))
	if err != nil {
		fmt.Printf("Error decoding creator sig string in checkCombine. ERR: (%s)", err.Error())
		t.FailNow()
	}

	combineArgs.OwnerSigs = make([][]byte, 0)
	combineArgs.PopcodePubKey, _ = hex.DecodeString(keys.pubKeyStr)
	combineArgs.PopcodeSig, err = hex.DecodeString(generateCombineSig(counter, combineArgs, int(combineArgs.Amount), combineArgs.Data, keys.privKeyStr))
	if err != nil {
		fmt.Printf("Error decoding creator sig string in checkCombine. ERR: (%s)", err.Error())
		t.FailNow()
	}

	combineArgsBytes, _ := proto.Marshal(&combineArgs)
	combineArgsBytesStr := hex.EncodeToString(combineArgsBytes)

	_, err = stub.MockInvoke("4", "combine", []string{combineArgsBytesStr})
	if err != nil {
		fmt.Printf("\nError invoking combine in checkCombine. ERR: (%s)", err.Error())
		t.FailNow()
	}
}

/*

	//To create new private and public keys
	privKeyString, err := newPrivateKeyString()
	if err != nil {
		fmt.Println(err)
	}
	pubKeyString, err := newPubKeyString(privKeyString)
	if err != nil {
		fmt.Println(err)
	}
*/
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

type keyInfo struct {
	privKeyStr string
	pubKeyStr  string
	address    string
}

/*
	checkCounterSeedChange creates 150 popcodes and checks that the counterseed changes at the appropriate time.
*/
func checkCounterSeedChange(t *testing.T, stub *shim.MockStub) {
	originalCounterseed, err := stub.GetState("CounterSeed")
	if err != nil {
		t.Error("error retrieving counterseed through counterseed query")
	}
	txCache := txcache.TXCache{}
	txCacheBytes, err := stub.GetState("TxCache")
	if err != nil {
		fmt.Println(err)
	}
	proto.Unmarshal(txCacheBytes, &txCache)
	//create up to 150 popcodes
	for i := len(txCache.Cache); i < 150; i++ {
		//create a new set of keys
		keys := new(keyInfo)
		keys.privKeyStr, err = newPrivateKeyString()
		if err != nil {
			fmt.Printf("error generating private key: %v", err)
		}
		keys.pubKeyStr, err = newPubKeyString(keys.privKeyStr)
		if err != nil {
			fmt.Printf("error generating public key: %v", err)
		}
		keys.address = newAddress(keys.pubKeyStr)

		//query balance to get counterSeed
		bytes, err := stub.MockQuery("balance", []string{keys.address})
		if err != nil {
			t.Errorf("query failure\n")
		}
		balanceResult := make(map[string]string)

		json.Unmarshal(bytes, &balanceResult)
		fmt.Println("Bracket Results")
		fmt.Println(string(bytes))

		//mint transaction with keys and counterseed
		altMint(t, stub, keys, balanceResult["Counter"])

		//check counterseed
		counterseed, err := stub.GetState("CounterSeed")
		if err != nil {
			t.Error("error retrieving counterseed through call to getState")
		}

		txCache := txcache.TXCache{}
		txCacheBytes, err := stub.GetState("TxCache")
		if err != nil {
			fmt.Println(err)
		}
		proto.Unmarshal(txCacheBytes, &txCache)

		fmt.Printf("\n\nCOUNTERSEEDSTRING: (%s)\ni: (%d)\nTXCACHELEN: (%d)\n\n\n", hex.EncodeToString(counterseed), i, len(txCache.Cache))

		//check for correct counterSeed value
		if (i < 101) && (hex.EncodeToString(counterseed) != hex.EncodeToString(originalCounterseed)) {
			t.Errorf("\nCounterseed got:\n(%s)\nwant:\n(%s)\n", hex.EncodeToString(counterseed), hex.EncodeToString(originalCounterseed))
			t.FailNow()
		}
		if expected := sha256.Sum256(originalCounterseed); i > 101 && (hex.EncodeToString(counterseed) != hex.EncodeToString(expected[:])) {
			t.Errorf("\nCounterseed got:\n(%s)\nwant:\n(%s)\n", hex.EncodeToString(counterseed), hex.EncodeToString(expected[:]))
			t.FailNow()

		}
	}
}

// func generateCombineSig(sources []Pop.SourceOutput, amount int, data string, privateKeyStr string) string {

func TestPopcodeChaincode(t *testing.T) {
	bst := new(tuxedoPopsChaincode)
	stub := shim.NewMockStub("tuxedoPops", bst)
	checkInit(t, stub, []string{"Hello World"})

	checkQuery(t, stub, "74ded2036e988fc56e3cff77a40c58239591e921", `{"Address":"74ded2036e988fc56e3cff77a40c58239591e921","Counter":"af5eef44907ccdcc33051d035f32f42de0d093fac2fd9d15923448f6af46bc43","Outputs":null}`)
	mint(t, stub, "af5eef44907ccdcc33051d035f32f42de0d093fac2fd9d15923448f6af46bc43")
	checkQuery(t, stub, "74ded2036e988fc56e3cff77a40c58239591e921", `{"Address":"74ded2036e988fc56e3cff77a40c58239591e921","Counter":"e91d1eab53d597e8e18bb9ebbbaec66d08187d7e14a4a58c8782610ce7c7a74b","Outputs":["{\"Owners\":null,\"Threshold\":0,\"Data\":\"Test Data\",\"Type\":\"Test Asset\",\"PrevCounter\":\"af5eef44907ccdcc33051d035f32f42de0d093fac2fd9d15923448f6af46bc43\",\"Creator\":\"03cc7d40833fdf46e05a7f86a6c9cf8a697a129fbae0676ad6bad71f163ea22b26\",\"Amount\":10}"]}`)
	mint(t, stub, "e91d1eab53d597e8e18bb9ebbbaec66d08187d7e14a4a58c8782610ce7c7a74b")
	checkQuery(t, stub, "74ded2036e988fc56e3cff77a40c58239591e921", `{"Address":"74ded2036e988fc56e3cff77a40c58239591e921","Counter":"1adb7c0c1b464fb45860355bf8e711312c608d01202197e58116a424f74af254","Outputs":["{\"Owners\":null,\"Threshold\":0,\"Data\":\"Test Data\",\"Type\":\"Test Asset\",\"PrevCounter\":\"af5eef44907ccdcc33051d035f32f42de0d093fac2fd9d15923448f6af46bc43\",\"Creator\":\"03cc7d40833fdf46e05a7f86a6c9cf8a697a129fbae0676ad6bad71f163ea22b26\",\"Amount\":10}","{\"Owners\":null,\"Threshold\":0,\"Data\":\"Test Data\",\"Type\":\"Test Asset\",\"PrevCounter\":\"e91d1eab53d597e8e18bb9ebbbaec66d08187d7e14a4a58c8782610ce7c7a74b\",\"Creator\":\"03cc7d40833fdf46e05a7f86a6c9cf8a697a129fbae0676ad6bad71f163ea22b26\",\"Amount\":10}"]}`)
	possess(t, stub, "1adb7c0c1b464fb45860355bf8e711312c608d01202197e58116a424f74af254", 1)
	checkQuery(t, stub, "74ded2036e988fc56e3cff77a40c58239591e921", `{"Address":"74ded2036e988fc56e3cff77a40c58239591e921","Counter":"d3e41e748a7094cc520319623479f97dfb6aae0ea915940b72926384fe8d0e8c","Outputs":["{\"Owners\":null,\"Threshold\":0,\"Data\":\"Test Data\",\"Type\":\"Test Asset\",\"PrevCounter\":\"af5eef44907ccdcc33051d035f32f42de0d093fac2fd9d15923448f6af46bc43\",\"Creator\":\"03cc7d40833fdf46e05a7f86a6c9cf8a697a129fbae0676ad6bad71f163ea22b26\",\"Amount\":10}","{\"Owners\":[\"0278b76afbefb1e1185bc63ed1a17dd88634e0587491f03e9a8d2d25d9ab289ee7\"],\"Threshold\":1,\"Data\":\"Test possess\",\"Type\":\"Test Asset\",\"PrevCounter\":\"1adb7c0c1b464fb45860355bf8e711312c608d01202197e58116a424f74af254\",\"Creator\":\"03cc7d40833fdf46e05a7f86a6c9cf8a697a129fbae0676ad6bad71f163ea22b26\",\"Amount\":10}"]}`)
	unitize(t, stub, "d3e41e748a7094cc520319623479f97dfb6aae0ea915940b72926384fe8d0e8c")
	checkQuery(t, stub, "74ded2036e988fc56e3cff77a40c58239591e921", `{"Address":"74ded2036e988fc56e3cff77a40c58239591e921","Counter":"afab4e267a433fe306d1da4608629ce9a280bde98f7004ff883383d65b9f5948","Outputs":["{\"Owners\":[\"0278b76afbefb1e1185bc63ed1a17dd88634e0587491f03e9a8d2d25d9ab289ee7\"],\"Threshold\":1,\"Data\":\"Test possess\",\"Type\":\"Test Asset\",\"PrevCounter\":\"1adb7c0c1b464fb45860355bf8e711312c608d01202197e58116a424f74af254\",\"Creator\":\"03cc7d40833fdf46e05a7f86a6c9cf8a697a129fbae0676ad6bad71f163ea22b26\",\"Amount\":10}"]}`)
	checkQuery(t, stub, "10734390011641497f489cb475743b8e50d429bb", `{"Address":"10734390011641497f489cb475743b8e50d429bb","Counter":"83b298acdf5d7231597ffb776c8f027877ca89cbafa7675a3f177619b0a9ad74","Outputs":["{\"Owners\":null,\"Threshold\":0,\"Data\":\"Test Unitize\",\"Type\":\"Test Asset\",\"PrevCounter\":\"d3e41e748a7094cc520319623479f97dfb6aae0ea915940b72926384fe8d0e8c\",\"Creator\":\"03cc7d40833fdf46e05a7f86a6c9cf8a697a129fbae0676ad6bad71f163ea22b26\",\"Amount\":10}"]}`)

	// registerRecipe(t, stub)
	// function := "recipe"
	// bytes, err := stub.MockQuery(function, []string{"test recipe"})
	// if err != nil {
	// 	fmt.Printf("Query (%s) failed. ERR: %v", function, err.Error())
	// 	t.FailNow()
	// }
	// if bytes == nil {
	// 	fmt.Printf("Query (%s) failed to get value\n", function)
	// 	t.FailNow()
	// }

	// // fmt.Printf("recipe query: (%v)\n\n", hex.EncodeToString(bytes))
	// var jsonMap map[string]interface{}
	// if err := json.Unmarshal(bytes, &jsonMap); err != nil {
	// 	fmt.Printf("error unmarshalling json string %s", bytes)
	// 	t.FailNow()
	// }
	// fmt.Printf("JSON: %s\n", jsonMap)

	checkCounterSeedChange(t, stub)
	checkCombine(t, stub)
}
