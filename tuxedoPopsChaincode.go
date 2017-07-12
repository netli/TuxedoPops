/*
Copyright (c) 2016 Skuchain,Inc

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"crypto/sha256"
	"strconv"

	"github.com/hyperledger/fabric/core/chaincode/shim"
	pb "github.com/hyperledger/fabric/protos/peer"

	"github.com/btcsuite/btcd/btcec"
	"github.com/golang/protobuf/proto"

	"github.com/skuchain/TuxedoPops/Pop"
	txcache "github.com/skuchain/TuxedoPops/TXCache"
	"github.com/skuchain/TuxedoPops/TuxedoPopsStore"
	"github.com/skuchain/TuxedoPops/TuxedoPopsTX"
	"github.com/skuchain/TuxedoPops/TxEvents"
)

// This chaincode implements the ledger operations for the proofchaincode

// ProofChainCode example simple Chaincode implementation
type tuxedoPopsChaincode struct {
}

func (t *tuxedoPopsChaincode) Init(stub shim.ChaincodeStubInterface) pb.Response {

	_, args := stub.GetFunctionAndParameters()

	if len(args) < 1 {
		fmt.Printf("Invalid Init Arg\n")
		return shim.Error(fmt.Sprintf("Invalid Init Arg\n"))
	}

	counterSeed := sha256.Sum256([]byte(args[0]))
	err := stub.PutState("CounterSeed", counterSeed[:])

	if err != nil {
		fmt.Printf("Error initializing CounterSeed\n")
		return shim.Error(fmt.Sprintf("Error initializing CounterSeed (%s)\n", args[0]))
	}

	return shim.Success(nil)
}

func (t *tuxedoPopsChaincode) Invoke(stub shim.ChaincodeStubInterface) pb.Response {

	function, args := stub.GetFunctionAndParameters()

	if function == "query" {
		return t.query(stub, args)
	}

	if len(args) == 0 {
		fmt.Println("Insufficient arguments found")
		return shim.Error("Insufficient arguments found\n")
	}

	argsBytes, err := hex.DecodeString(args[0])
	if err != nil {
		fmt.Printf("Invalid argument (%v) expected hex\n", args[0])
		return shim.Error(fmt.Sprintf("Invalid argument (%v) expected hex\n", args[0]))
	}

	counterseed, err := stub.GetState("CounterSeed")
	if err != nil {
		fmt.Printf("error getting counterseed state\n")
		return shim.Error("error getting counterseed state\n")
	}

	txCache := txcache.TXCache{}
	txCacheBytes, err := stub.GetState("TxCache")

	if err != nil {
		fmt.Println(err)
		return shim.Error(fmt.Sprintf("error getting TxCache state: %s\n", err.Error()))
	}

	if len(txCacheBytes) > 0 {
		proto.Unmarshal(txCacheBytes, &txCache)
	} else {
		txCache.Cache = make(map[string]bool)
	}

	switch function {
	case "create":

		createEvent := TxEvents.CreateEvent{}

		createArgs := TuxedoPopsTX.CreateTX{}
		err = proto.Unmarshal(argsBytes, &createArgs)
		if err != nil {
			fmt.Printf("Invalid argument expected CreateTX protocol buffer ERR:(%s)\n", err.Error())
			return shim.Error(fmt.Sprintf("Invalid argument expected CreateTX protocol buffer ERR:(%s)\n", err.Error()))
		}

		createEvent.Address = createArgs.Address
		createEvent.Amount = createArgs.Amount
		createEvent.CreatorPubKey = createArgs.CreatorPubKey
		createEvent.Data = createArgs.Data
		createEvent.Type = createArgs.Type

		popcodebytes, err := stub.GetState("Popcode:" + createArgs.Address)

		if err != nil {
			fmt.Println("Could not get Popcode State")
			return shim.Error("Could not get Popcode State")
		}
		popcode := Pop.Pop{}

		if len(popcodebytes) == 0 {
			addrBytes, err := hex.DecodeString(createArgs.Address)
			if err != nil {
				return shim.Error(fmt.Sprintf("Invalid popcode address %s ", createArgs.Address))
			}
			hasher := sha256.New()
			hasher.Write(counterseed)
			hasher.Write(addrBytes)
			hashedCounterSeed := []byte{}
			hashedCounterSeed = hasher.Sum(hashedCounterSeed)
			popcode.Counter = hashedCounterSeed[:]
			createEvent.SourceCounter = hashedCounterSeed[:]
			popcode.Address = hex.EncodeToString(addrBytes)

			err = popcode.CreateOutput(int(createArgs.Amount), createArgs.Type, createArgs.Data, createArgs.CreatorPubKey, createArgs.CreatorSig)
			if err != nil {
				fmt.Printf(err.Error())
				return shim.Error(err.Error())
			}
			createEvent.DestCounter = popcode.Outputs[len(popcode.Outputs)-1].PrevCounter

			antiReplayDigest := sha256.Sum256(createArgs.CreatorSig) // WARNING Assumes the Creator sig is not malleable without private key. Need to check if all maleability vectors are checked

			if txCache.Cache[string(antiReplayDigest[:])] {
				fmt.Printf("Already recieved transaction")
				return shim.Error("Already recieved transaction")
			}
			if len(txCache.Cache) > 100 {
				nextseed := sha256.Sum256(counterseed)
				counterseed = nextseed[:]
				txCache.Cache = make(map[string]bool)
			}

		} else {
			err := popcode.FromBytes(popcodebytes)
			if err != nil {
				fmt.Println("Popcode Deserialization error")
				return shim.Error("Popcode Deserialization Failure")
			}
			createEvent.SourceCounter = popcode.Counter
			err = popcode.CreateOutput(int(createArgs.Amount), createArgs.Type, createArgs.Data, createArgs.CreatorPubKey, createArgs.CreatorSig)
			if err != nil {
				fmt.Printf(err.Error())
				return shim.Error(err.Error())
			}
			createEvent.DestCounter = popcode.Outputs[len(popcode.Outputs)-1].PrevCounter

		}

		sigHash := sha256.Sum256(createArgs.CreatorSig[:])
		cacheIndex := hex.EncodeToString(sigHash[:])
		txCache.Cache[cacheIndex] = true
		err = stub.PutState("Popcode:"+createArgs.Address, popcode.ToBytes())
		if err != nil {
			fmt.Printf(err.Error())
			return shim.Error(err.Error())
		}
		createEventBytes, err := proto.Marshal(&createEvent)
		if err != nil {
			fmt.Printf(err.Error())
			return shim.Error(err.Error())
		}
		stub.SetEvent("create", createEventBytes)

	case "transfer":
		transferEvent := TxEvents.TransferEvent{}

		transferArgs := TuxedoPopsTX.TransferOwners{}
		err = proto.Unmarshal(argsBytes, &transferArgs)
		if err != nil {
			fmt.Println("Invalid argument expected TransferOwners protocol buffer")
			return shim.Error(fmt.Sprintf("Invalid argument expected TransferOwners protocol buffer %s", err.Error()))
		}

		transferEvent.Address = transferArgs.Address
		transferEvent.Data = transferArgs.Data
		transferEvent.Owners = transferArgs.Owners
		if len(transferArgs.Owners) < int(transferArgs.Threshold) {
			return shim.Error(fmt.Sprintf("threshold value (%d) is larger than number of owners (%d) for popcode output on address (%s)",
				transferArgs.Threshold, len(transferArgs.Owners), transferArgs.Address))
		}
		transferEvent.Threshold = transferArgs.Threshold

		popcodeKeyDigest := sha256.Sum256(transferArgs.PopcodePubKey)
		transferAddress := hex.EncodeToString(popcodeKeyDigest[:20])

		if transferAddress != transferArgs.Address {
			return shim.Error(fmt.Sprintf("Public key %s does not derive address of %s", transferArgs.PopcodePubKey, transferArgs.Address))
		}

		popcodebytes, err := stub.GetState("Popcode:" + transferArgs.Address)
		if err != nil {
			fmt.Println("Could not get Popcode State")
			return shim.Error("Could not get Popcode State")
		}
		if len(popcodebytes) == 0 {
			fmt.Println("No value found in popcode")
			return shim.Error("No value found in popcode")
		}
		popcode := Pop.Pop{}
		popcode.FromBytes(popcodebytes)

		if transferArgs.Output < 0 || int(transferArgs.Output) >= len(popcode.Outputs) {
			shim.Error(fmt.Sprintf("Invalid Output index %d %s", transferArgs.Output, popcode.ToJSON()))
		}
		transferEvent.SourceCounter = popcode.Outputs[transferArgs.Output].PrevCounter

		err = popcode.SetOwner(int(transferArgs.Output), int(transferArgs.Threshold), transferArgs.Data, transferArgs.Owners, transferArgs.PrevOwnerSigs, transferArgs.PopcodePubKey, transferArgs.PopcodeSig)
		if err != nil {
			fmt.Printf(err.Error())
			return shim.Error(err.Error())
		}

		transferEvent.DestCounter = popcode.Outputs[transferArgs.Output].PrevCounter
		transferEvent.Amount = int32(popcode.Outputs[transferArgs.Output].Amount)
		transferEvent.Type = popcode.Outputs[transferArgs.Output].Type

		err = stub.PutState("Popcode:"+transferArgs.Address, popcode.ToBytes())
		if err != nil {
			fmt.Printf(err.Error())
			return shim.Error(err.Error())
		}
		transferEventBytes, err := proto.Marshal(&transferEvent)
		if err != nil {
			fmt.Printf(err.Error())
			return shim.Error(err.Error())
		}
		stub.SetEvent("transfer", transferEventBytes)

	case "unitize":
		unitizeEvent := TxEvents.UnitizeEvent{}
		unitizeArgs := TuxedoPopsTX.Unitize{}
		err = proto.Unmarshal(argsBytes, &unitizeArgs)
		if err != nil {
			fmt.Println("Invalid argument expected Unitize protocol buffer")
			return shim.Error(fmt.Sprintf("Invalid argument expected Unitize protocol buffer %s", err.Error()))
		}

		if unitizeArgs.SourceAddress == unitizeArgs.DestAddress {
			return shim.Error(fmt.Sprintf("The source address %s must be different from dest address %s", unitizeArgs.SourceAddress, unitizeArgs.DestAddress))
		}
		fmt.Printf("\n\n\nOWNERSIGS for UNITIZE: (%v)\n\n", unitizeArgs.OwnerSigs)

		unitizeEvent.Data = unitizeArgs.Data
		unitizeEvent.DestAddress = unitizeArgs.DestAddress
		unitizeEvent.PopcodePubKey = unitizeArgs.PopcodePubKey
		unitizeEvent.SourceAddress = unitizeArgs.SourceAddress
		unitizeEvent.SourceOutput = unitizeArgs.SourceOutput

		popcodeKeyDigest := sha256.Sum256(unitizeArgs.PopcodePubKey)
		sourceAddress := hex.EncodeToString(popcodeKeyDigest[:20])
		if unitizeArgs.SourceAddress != sourceAddress {
			return shim.Error(fmt.Sprintf("Public key %s does not derive address of %s", unitizeArgs.PopcodePubKey, unitizeArgs.SourceAddress))
		}
		sourcePopcodeBytes, err := stub.GetState("Popcode:" + sourceAddress)
		if err != nil {
			fmt.Println("Could not get Popcode State")
			return shim.Error(fmt.Sprintf("Could not get Popcode State"))
		}
		if len(sourcePopcodeBytes) == 0 {
			fmt.Println("No value found in popcode")
			return shim.Error(fmt.Sprintf("No value found in popcode"))
		}
		sourcePopcode := Pop.Pop{}
		err = sourcePopcode.FromBytes(sourcePopcodeBytes)
		if err != nil {
			fmt.Println("Could not get Popcode State")
			return shim.Error(fmt.Sprintf("Could not get Popcode State"))
		}

		if unitizeArgs.SourceOutput < 0 || int(unitizeArgs.SourceOutput) >= len(sourcePopcode.Outputs) {
			return shim.Error(fmt.Sprintf("Invalid Output index %d %s", unitizeArgs.SourceOutput, sourcePopcode.ToJSON()))
		}
		unitizeEvent.SourceCounter = sourcePopcode.Outputs[unitizeArgs.SourceOutput].PrevCounter
		destAddress := unitizeArgs.DestAddress
		destPopcodeBytes, err := stub.GetState("Popcode:" + destAddress)
		if err != nil {
			return shim.Error("Could not get Popcode State")
		}
		destPopcode := Pop.Pop{}
		if len(destPopcodeBytes) == 0 {
			destAddressBytes, err := hex.DecodeString(destAddress)
			if err != nil {
				return shim.Error(fmt.Sprintf("Invalid address %s", destAddress))
			}
			hasher := sha256.New()
			hasher.Write(sourcePopcode.Counter)
			hasher.Write(destAddressBytes)
			hashedCounterSeed := []byte{}
			hashedCounterSeed = hasher.Sum(hashedCounterSeed)
			destPopcode.Address = unitizeArgs.DestAddress
			destPopcode.Counter = hashedCounterSeed[:]
		} else {
			err = destPopcode.FromBytes(destPopcodeBytes)
			if err != nil {
				fmt.Println("Dest Popcode Deserialization error")
				return shim.Error("Dest Popcode Deserialization Failure")
			}
		}
		convertedAmounts := make([]int, len(unitizeArgs.DestAmounts))
		for i, destAmount := range unitizeArgs.DestAmounts {
			convertedAmounts[i] = int(destAmount)
		}
		err = sourcePopcode.UnitizeOutput(int(unitizeArgs.SourceOutput), convertedAmounts, unitizeArgs.Data,
			&destPopcode, unitizeArgs.OwnerSigs, unitizeArgs.PopcodePubKey, unitizeArgs.PopcodeSig)
		if err != nil {
			fmt.Printf("Unitize error: %s", err.Error())
			return shim.Error(fmt.Sprintf("Unitize error: %s", err.Error()))
		}

		// The idea here is to harvest the created Counter values for the destinations via revserse interation through the number of events coordinated
		for index := len(destPopcode.Outputs) - 1; index > len(destPopcode.Outputs)-1-len(unitizeArgs.DestAmounts); index-- {
			fmt.Printf("\x1b[32m\n\n\ndestPopcode.Address: (%s)\ndestpopcode.Outputs: (%v)\nindex: (%d)\nnumber of destination amounts: (%d)\nstopping condition: index <= (%d)\n\n\x1b[0m",
				destPopcode.Address, destPopcode.Outputs, index, len(unitizeArgs.DestAmounts), len(destPopcode.Outputs)-1-len(unitizeArgs.DestAmounts))

			unitizeEvent.DestCounters = append(unitizeEvent.DestCounters, destPopcode.Outputs[index].PrevCounter)
			unitizeEvent.DestAmounts = append(unitizeEvent.DestAmounts, int32(destPopcode.Outputs[index].Amount))
		}

		err = stub.PutState("Popcode:"+sourceAddress, sourcePopcode.ToBytes())
		if err != nil {
			fmt.Printf(err.Error())
			return shim.Error(err.Error())
		}
		err = stub.PutState("Popcode:"+destAddress, destPopcode.ToBytes())
		if err != nil {
			fmt.Printf(err.Error())
			return shim.Error(err.Error())
		}
		unitizeEventBytes, err := proto.Marshal(&unitizeEvent)
		if err != nil {
			fmt.Printf(err.Error())
			return shim.Error(err.Error())
		}
		stub.SetEvent("unitize", unitizeEventBytes)

	case "combine":

		combineEvent := TxEvents.CombineEvent{}
		combineArgs := TuxedoPopsTX.Combine{}

		err = proto.Unmarshal(argsBytes, &combineArgs)
		if err != nil {
			fmt.Println("Invalid argument expected Combine protocol buffer")
			return shim.Error(fmt.Sprintf("Invalid argument expected Combine protocol buffer %s", err.Error()))
		}
		combineEvent.Address = combineArgs.Address
		combineEvent.Amount = combineArgs.Amount
		combineEvent.CreatorPubKey = combineArgs.CreatorPubKey
		combineEvent.Data = combineArgs.Data
		combineEvent.Recipe = combineArgs.Recipe

		for _, source := range combineArgs.Sources {
			evSource := TxEvents.CombineSources{}
			evSource.SourceAmount = source.SourceAmount
			evSource.SourceOutput = source.SourceOutput
			combineEvent.Sources = append(combineEvent.Sources, &evSource)
		}

		popcodeKeyDigest := sha256.Sum256(combineArgs.PopcodePubKey)
		combineAddress := hex.EncodeToString(popcodeKeyDigest[:20])
		if combineAddress != combineArgs.Address {
			return shim.Error(fmt.Sprintf("Public key %s does not derive address of %s", combineArgs.PopcodePubKey, combineArgs.Address))
		}

		popcode := Pop.Pop{}
		popcodeBytes, err := stub.GetState("Popcode:" + combineAddress)
		if err != nil {
			fmt.Println("Could not get Popcode State")
			shim.Error("Could not get Popcode State")
		}
		if len(popcodeBytes) == 0 {
			fmt.Println("No value found in popcode")
			shim.Error("No value found in popcode")
		}
		popcode.FromBytes(popcodeBytes)

		recipeBytes, err := stub.GetState("Recipe:" + combineArgs.Recipe)

		if err != nil {
			fmt.Println("Could not get Recipe State")
			shim.Error("Could not get Recipe State")
		}
		if len(recipeBytes) == 0 {
			fmt.Printf("Recipe %s not registered", combineArgs.Recipe)
			return shim.Error(fmt.Sprintf("Recipe %s is not registered", combineArgs.Recipe))
		}
		recipe := TuxedoPopsStore.Recipe{}
		err = proto.Unmarshal(recipeBytes, &recipe)
		if err != nil {
			return shim.Error(fmt.Sprintf("Could not deserialize Recipe %s", combineArgs.Recipe))
		}

		sources := make([]Pop.SourceOutput, len(combineArgs.Sources))

		for i, v := range combineArgs.Sources {
			sources[i] = v

			if v.Idx() < len(popcode.Outputs) {
				combineEvent.SourceCounters = append(combineEvent.SourceCounters, popcode.Outputs[v.Idx()].PrevCounter)
			} else {
				return shim.Error(fmt.Sprintf("Invalid output index in combine %d", v.Idx()))
			}

		}

		err = popcode.CombineOutputs(sources, combineArgs.OwnerSigs, combineArgs.PopcodePubKey, combineArgs.PopcodeSig,
			int(combineArgs.Amount), combineArgs.Recipe, recipe, combineArgs.Data, combineArgs.CreatorPubKey, combineArgs.CreatorSig)
		if err != nil {
			fmt.Printf(err.Error())
			return shim.Error(err.Error())
		}
		combineEvent.DestCounter = popcode.Outputs[len(popcode.Outputs)-1].PrevCounter

		err = stub.PutState("Popcode:"+combineAddress, popcode.ToBytes())
		if err != nil {
			fmt.Printf(err.Error())
			return shim.Error(err.Error())
		}
		combineEventBytes, err := proto.Marshal(&combineEvent)
		if err != nil {
			fmt.Printf(err.Error())
			return shim.Error(err.Error())
		}
		stub.SetEvent("combine", combineEventBytes)

	case "recipe":
		recipeArgs := TuxedoPopsTX.Recipe{}
		err = proto.Unmarshal(argsBytes, &recipeArgs)
		if err != nil {
			fmt.Println("Invalid argument expected Recipe protocol buffer")
			return shim.Error(fmt.Sprintf("Invalid argument expected Recipe protocol buffer %s", err.Error()))
		}
		recipeBytes, err := stub.GetState("Recipe:" + recipeArgs.RecipeName)
		if err != nil {
			fmt.Println("Could not get Recipe State")
			return shim.Error(fmt.Sprintf("Could not get Recipe (%s) state\n", recipeArgs.RecipeName))
		}

		//if recipe already exists
		if len(recipeBytes) != 0 {
			fmt.Printf("Recipe (%s) already registered\n", recipeArgs.RecipeName)
			return shim.Error(fmt.Sprintf("Recipe (%s) already registered\n", recipeArgs.RecipeName))
		}

		creatorPubKey, err := btcec.ParsePubKey(recipeArgs.CreatorPubKey, btcec.S256())
		if err != nil {
			return shim.Error(fmt.Sprintf("Could not deserialize Creator Pub Key (%v)", recipeArgs.CreatorPubKey))
		}

		creatorSig, err := btcec.ParseDERSignature(recipeArgs.CreatorSig, btcec.S256())

		if err != nil {
			return shim.Error(fmt.Sprintf("Could not deserialize Creator Signature (%v)", recipeArgs.CreatorSig))
		}

		message := recipeArgs.RecipeName + ":" + recipeArgs.CreatedType
		for _, ingredient := range recipeArgs.Ingredients {
			message += ":" + strconv.FormatInt(int64(ingredient.Numerator), 10) + ":" +
				strconv.FormatInt(int64(ingredient.Denominator), 10) + ":" + ingredient.Type
		}
		messageBytes := sha256.Sum256([]byte(message))
		success := creatorSig.Verify(messageBytes[:], creatorPubKey)
		if !success {
			// fmt.Printf("Invalid Creator Signature (%+v)\n", creatorSig)
			return shim.Error(fmt.Sprintf("Invalid Creator Signature (%+v)\n", creatorSig))
		}

		recStore := TuxedoPopsStore.Recipe{}
		recStore.CreatedType = recipeArgs.CreatedType
		recStore.Creator = recipeArgs.CreatorPubKey
		for _, ingredient := range recipeArgs.Ingredients {
			ingredientStore := TuxedoPopsStore.Ingredient{}
			ingredientStore.Numerator = int64(ingredient.Numerator)
			ingredientStore.Denominator = int64(ingredient.Denominator)
			ingredientStore.Type = ingredient.Type
			recStore.Ingredients = append(recStore.Ingredients, &ingredientStore)
		}
		recStoreBytes, err := proto.Marshal(&recStore)
		if err != nil {
			fmt.Printf("Recipe Store Serialization error\n")
			return shim.Error(fmt.Sprintf("Recipe Store Serialization Error\n"))
		}
		fmt.Printf("PUTTING RECIPE (%s) TO LEDGER\n", recipeArgs.RecipeName)
		err = stub.PutState("Recipe:"+recipeArgs.RecipeName, recStoreBytes)
		if err != nil {
			fmt.Printf("error putting recipe state to ledger: (%s)\n", err.Error())
			return shim.Error(fmt.Sprintf("error putting recipe state to ledger: (%s)\n", err.Error()))
		}
	default:
		fmt.Printf("Invalid function type (%s)", function)
		return shim.Error(fmt.Sprintf("Invalid function type (%s)", function))
	}
	txCacheBytes, err = proto.Marshal(&txCache)
	if err != nil {
		fmt.Printf("error marshalling txCache in invoke: (%v)\n", err.Error())
		return shim.Error(fmt.Sprintf("error marshalling txCache in invoke: (%v)\n", err.Error()))
	}
	if len(txCacheBytes) > 0 {
		err = stub.PutState("TxCache", txCacheBytes)
	}
	if err != nil {
		fmt.Printf("error putting txCache to ledger in invoke: (%v)\n", err.Error())
		return shim.Error(fmt.Sprintf("error putting txCache to ledger in invoke: (%v)\n", err.Error()))
	}
	err = stub.PutState("CounterSeed", counterseed)
	if err != nil {
		fmt.Printf("Error putting counterseed to ledger in invoke: (%v)\n", err.Error())
		return shim.Error(fmt.Sprintf("Error putting counterseed to ledger in invoke: (%v)\n", err.Error()))
	}
	return shim.Success(nil)
}

func recipeToJSON(createdType string, ingredients []*TuxedoPopsStore.Ingredient, creatorPubKey []byte) ([]byte, error) {
	type JSONRecipe struct {
		CreatedType string
		Ingredients []*TuxedoPopsStore.Ingredient
		Creator     string
	}
	jsonRecipe := JSONRecipe{}
	jsonRecipe.CreatedType = createdType
	jsonRecipe.Ingredients = ingredients
	jsonRecipe.Creator = hex.EncodeToString(creatorPubKey)

	jsonstring, err := json.Marshal(jsonRecipe)
	if err != nil {
		return nil, err
	}
	return jsonstring, nil
}

func (t *tuxedoPopsChaincode) query(stub shim.ChaincodeStubInterface, args []string) pb.Response {

	fmt.Printf("query_type: %s", args[0])
	switch args[0] {
	case "balance":
		if len(args) != 2 {
			return shim.Error(fmt.Sprintf("Must have 2 arguments to query[balance]. Received %d", len(args)))
		}
		counterseed, err := stub.GetState("CounterSeed")

		if err != nil {
			fmt.Printf(err.Error())
			return shim.Error(err.Error())
		}

		address := args[0]
		popcode := Pop.Pop{}
		popcodeBytes, err := stub.GetState("Popcode:" + address)
		if err != nil {
			fmt.Printf(err.Error())
			return shim.Error(err.Error())
		}
		if len(popcodeBytes) == 0 {
			addrBytes, _ := hex.DecodeString(address)
			hasher := sha256.New()
			hasher.Write(counterseed)
			hasher.Write(addrBytes)
			hashedCounterSeed := []byte{}
			hashedCounterSeed = hasher.Sum(hashedCounterSeed)
			popcode.Address = args[0]
			popcode.Counter = hashedCounterSeed
			fmt.Printf("The popcode JSON is %s", popcode.ToJSON())
			return shim.Success(popcode.ToJSON())
		}
		popcode.FromBytes(popcodeBytes)
		fmt.Printf("The popcode JSON is %s", popcode.ToJSON())
		return shim.Success(popcode.ToJSON())
	case "recipe":
		if len(args) != 2 {
			return shim.Error(fmt.Sprintf("Must have 2 arguments to query[recipe]. Received %d", len(args)))
		}

		recipe := TuxedoPopsStore.Recipe{}
		recipeName := args[0]

		recipeBytes, err := stub.GetState("Recipe:" + recipeName)
		if err != nil {
			fmt.Printf(err.Error())
			return shim.Error(fmt.Sprintf("ERR: (%v)\n", err.Error()))
		}

		if len(recipeBytes) == 0 {
			return shim.Error(fmt.Sprintf("recipe (%s) does not exist\n", recipeName))
		}

		err = proto.Unmarshal(recipeBytes, &recipe)
		if err != nil {
			fmt.Printf(err.Error())
			return shim.Error(fmt.Sprintf("ERR: (%v)", err.Error()))
		}

		jsonBytes, err := recipeToJSON(recipe.CreatedType, recipe.Ingredients, recipe.Creator)
		if err != nil {
			fmt.Printf(err.Error())
			return shim.Error(err.Error())
		}
		return shim.Success(jsonBytes)
	}
	return shim.Success(nil)
}

func main() {
	err := shim.Start(new(tuxedoPopsChaincode))
	if err != nil {
		fmt.Printf("Error starting chaincode: %s\n", err)
	}
}
