package main

import (
	"crypto/sha256"
	"fmt"
	"strconv"
	"testing"

	"encoding/hex"
	"encoding/json"

	"github.com/golang/protobuf/proto"

	"github.com/btcsuite/btcd/btcec"
	"github.com/hyperledger/fabric/core/chaincode/shim"
	"github.com/skuchain/TuxedoPops/TuxedoPopsTX"
)

func testCombine(t *testing.T, stub *shim.MockStub, popcodes *popcodes, users *users, recipeName string, owners []*keyInfo) {
	popcode := popcodes.popcode2
	sources := []*TuxedoPopsTX.CombineSources{}
	source := new(TuxedoPopsTX.CombineSources)
	source.SourceOutput = 0
	source.SourceAmount = 1
	sources = append(sources, source)
	creator := users.user2
	data := "data"
	amount := 1
	// recipeName = "Water Vapor Recipe"

	popcodeBalance := getBalance(t, stub, popcodes.popcode2)
	fmt.Printf("\n\npopcode balance: (%v)\n\n", popcodeBalance)

	prevCounter := popcodeBalance.Counter
	prevNumberOfOutputs := len(popcodeBalance.Outputs)
	combine(t, stub, popcode, sources, int32(amount), recipeName, creator, owners, data)
	popcodeBalance = getBalance(t, stub, popcodes.popcode2)
	if popcodeBalance.Counter == prevCounter {
		HandleError(t, fmt.Errorf("Counter of popcode (%s) did not change after call to combine\n", popcode.address))
	}
	if len(popcodeBalance.Outputs) == prevNumberOfOutputs {
		HandleError(t, fmt.Errorf("Number of outputs of popcode (%d) did not change after call to combine"+
			"\npopcode balance: (%v)", len(popcodeBalance.Outputs), popcodeBalance))
	}
	fmt.Printf("popcode balance: (%v)\n\n", popcodeBalance)
}

func hardCodedRecipe(t *testing.T, stub *shim.MockStub) {
	recipeArgs := TuxedoPopsTX.Recipe{}
	recipeArgs.RecipeName = "test recipe"
	recipeArgs.CreatedType = "water vapor"
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
		HandleError(t, fmt.Errorf("error decoding creator signature in register recipe. ERR: (%v)", err.Error()))
		t.FailNow()
	}
	recipeArgsBytes, err := proto.Marshal(&recipeArgs)
	if err != nil {
		HandleError(t, fmt.Errorf("error marshalling recipeArgs in registerRecipe. ERR: (%s)\n", err.Error()))
		t.FailNow()
	}
	recipeArgsBytesStr := hex.EncodeToString(recipeArgsBytes)
	_, err = stub.MockInvoke("4", "recipe", []string{recipeArgsBytesStr})
	if err != nil {
		HandleError(t, err)
		t.Errorf("error invoking recipe: (%v)", err.Error())
	}
}

func hardCodedCombine(t *testing.T, stub *shim.MockStub) {
	hardCodedRecipe(t, stub)
	function := "recipe"
	bytes, err := stub.MockQuery(function, []string{"test recipe"})
	if err != nil {
		HandleError(t, fmt.Errorf("Query (%s) failed. ERR: %v", function, err.Error()))
		t.FailNow()
	}
	if bytes == nil {
		HandleError(t, fmt.Errorf("Query (%s) failed to get value\n", function))
		t.FailNow()
	}

	var jsonMap map[string]interface{}
	if err := json.Unmarshal(bytes, &jsonMap); err != nil {
		HandleError(t, fmt.Errorf("error unmarshalling json string %s", bytes))
		t.FailNow()
	}
	fmt.Printf("JSON: %s\n", jsonMap)

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

	//mint value in popcode through create transaction with keys and counterseed
	mint(t, stub, user, popcode, "Test Data", "Test Asset", 10)
	popcode.counter, err = getCounter(stub, popcode)
	if err != nil {
		HandleError(t, fmt.Errorf("error retrieving counterseed: (%v)", err.Error()))
		t.FailNow()
	}

	//perform combination
	combineArgs := TuxedoPopsTX.Combine{}
	combineArgs.Address = popcode.address
	//Sources
	source := new(TuxedoPopsTX.CombineSources)
	source.SourceAmount = 10
	source.SourceOutput = 0
	combineArgs.Sources = append(combineArgs.Sources, source)

	combineArgs.Amount = 10
	combineArgs.Recipe = "test recipe"
	combineArgs.Data = "test data"

	creatorPrivKey, _ := newPrivateKeyString()
	creatorPubKeyStr, _ := newPubKeyString(creatorPrivKey)

	combineArgs.CreatorPubKey, _ = hex.DecodeString(creatorPubKeyStr)
	if err != nil {
		HandleError(t, fmt.Errorf("generating private key: %v", err.Error()))
		t.FailNow()
	}

	combineArgs.CreatorSig = generateCombineSig(popcode.counter, combineArgs,
		int(combineArgs.Amount), combineArgs.Data, creatorPrivKey)

	combineArgs.OwnerSigs = make([][]byte, 0)
	combineArgs.PopcodePubKey, _ = hex.DecodeString(popcode.pubKeyStr)
	combineArgs.PopcodeSig = generateCombineSig(popcode.counter, combineArgs,
		int(combineArgs.Amount), combineArgs.Data, popcode.privKeyStr)

	combineArgsBytes, _ := proto.Marshal(&combineArgs)
	combineArgsBytesStr := hex.EncodeToString(combineArgsBytes)

	_, err = stub.MockInvoke("4", "combine", []string{combineArgsBytesStr})
	if err != nil {
		HandleError(t, fmt.Errorf("\nError invoking combine in checkCombine. ERR: (%s)", err.Error()))
		t.FailNow()
	}
}

func recipe(t *testing.T, stub *shim.MockStub, recipeName string, createdType string,
	creator *keyInfo, ingredients []*TuxedoPopsTX.Ingredient) {

	recipeArgs := TuxedoPopsTX.Recipe{}
	recipeArgs.RecipeName = recipeName
	recipeArgs.CreatedType = createdType
	var err error
	recipeArgs.CreatorPubKey, err = hex.DecodeString(creator.pubKeyStr)
	if err != nil {
		HandleError(t, err)
		t.FailNow()
	}
	recipeArgs.Ingredients = ingredients

	sigHex := generateRecipeSig(recipeArgs.RecipeName, recipeArgs.CreatedType,
		recipeArgs.Ingredients, creator.privKeyStr)

	recipeArgs.CreatorSig, err = hex.DecodeString(sigHex)
	if err != nil {
		HandleError(t, fmt.Errorf("error decoding creator signature in recipe. ERR: (%v)", err.Error()))
		t.FailNow()
	}
	recipeArgsBytes, err := proto.Marshal(&recipeArgs)
	if err != nil {
		HandleError(t, fmt.Errorf("error marshalling recipeArgs in recipe. ERR: (%s)\n", err.Error()))
		t.FailNow()
	}
	recipeArgsBytesStr := hex.EncodeToString(recipeArgsBytes)
	_, err = stub.MockInvoke("4", "recipe", []string{recipeArgsBytesStr})
	if err != nil {
		HandleError(t, fmt.Errorf("error invoking recipe: (%v)", err.Error()))
		t.FailNow()
	}
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

/*
	COMBINE
	combination transaction with two owners
*/
func combine(t *testing.T, stub *shim.MockStub, popcode *keyInfo, sources []*TuxedoPopsTX.CombineSources,
	amount int32, recipe string, creator *keyInfo, owners []*keyInfo, data string) {

	var err error
	combineArgs := TuxedoPopsTX.Combine{}
	combineArgs.Address = popcode.address
	combineArgs.Sources = sources
	combineArgs.Amount = amount
	combineArgs.Recipe = recipe
	combineArgs.Data = data

	combineArgs.CreatorPubKey, err = hex.DecodeString(creator.pubKeyStr)
	if err != nil {
		HandleError(t, fmt.Errorf("error decoding public key: %v", err.Error()))
		t.FailNow()
	}

	popcode.counter, err = getCounter(stub, popcode)
	if err != nil {
		t.Errorf("error retrieving counterseed: (%v)", err.Error())
		t.FailNow()
	}
	combineArgs.CreatorSig = generateCombineSig(popcode.counter, combineArgs,
		int(combineArgs.Amount), combineArgs.Data, creator.privKeyStr)

	combineArgs.OwnerSigs = make([][]byte, 0)

	for _, owner := range owners {
		if owner != nil {
			ownerSig := generateCombineSig(popcode.counter, combineArgs,
				int(combineArgs.Amount), combineArgs.Data, owner.privKeyStr)

			combineArgs.OwnerSigs = append(combineArgs.OwnerSigs, ownerSig)
		}
	}
	combineArgs.PopcodePubKey, err = hex.DecodeString(popcode.pubKeyStr)
	if err != nil {
		HandleError(t, err)
		t.FailNow()
	}
	combineArgs.PopcodeSig = generateCombineSig(popcode.counter, combineArgs,
		int(combineArgs.Amount), combineArgs.Data, popcode.privKeyStr)

	combineArgsBytes, _ := proto.Marshal(&combineArgs)
	combineArgsBytesStr := hex.EncodeToString(combineArgsBytes)

	_, err = stub.MockInvoke("4", "combine", []string{combineArgsBytesStr})
	if err != nil {
		HandleError(t, fmt.Errorf("\nError invoking combine in checkCombine. ERR: (%s)", err.Error()))
		t.FailNow()
	}
}

func generateCombineSig(counter string, combine TuxedoPopsTX.Combine, amount int, data string,
	privateKeyStr string) []byte {

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

	return sig.Serialize()
}
