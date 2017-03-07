/*
Copyright (c) 2016 Skuchain,Inc

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
package main

import (
	"encoding/hex"
	"fmt"

	"crypto/sha256"

	"errors"

	"strconv"

	"github.com/btcsuite/btcd/btcec"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/core/chaincode/shim"
	"github.com/skuchain/TuxedoPops/Pop"
	txcache "github.com/skuchain/TuxedoPops/TXCache"
	"github.com/skuchain/TuxedoPops/TuxedoPopsStore"
	"github.com/skuchain/TuxedoPops/TuxedoPopsTX"
)

// This chaincode implements the ledger operations for the proofchaincode

// ProofChainCode example simple Chaincode implementation
type tuxedoPopsChaincode struct {
}

func (t *tuxedoPopsChaincode) Init(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	if len(args) < 1 {
		fmt.Printf("Invalid Init Arg")
		return nil, errors.New("Invalid Init Arg")
	}

	counterSeed := sha256.Sum256([]byte(args[0]))

	err := stub.PutState("CounterSeed", counterSeed[:])

	if err != nil {
		fmt.Printf("Error initializing CounterSeed")
		return nil, errors.New("Error initializing CounterSeed")
	}

	return nil, nil
}

func (t *tuxedoPopsChaincode) Invoke(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	if len(args) == 0 {
		fmt.Println("Insufficient arguments found")
		return nil, errors.New("Insufficient arguments found")
	}

	argsBytes, err := hex.DecodeString(args[0])
	if err != nil {
		fmt.Println("Invalid argument expected hex")
		return nil, errors.New("Invalid argument expected hex")
	}

	counterseed, err := stub.GetState("CounterSeed")
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	txCache := txcache.TXCache{}
	txCacheBytes, err := stub.GetState("TxCache")

	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	if len(txCacheBytes) > 0 {
		proto.Unmarshal(txCacheBytes, &txCache)
	} else {
		txCache.Cache = make(map[string]bool)
	}

	switch function {
	case "create":
		createArgs := TuxedoPopsTX.CreateTX{}
		err = proto.Unmarshal(argsBytes, &createArgs)
		if err != nil {
			fmt.Println("Invalid argument expected CreateTX protocol buffer")
			return nil, fmt.Errorf("Invalid argument expected CreateTX protocol buffer %s", err.Error())
		}

		popcodebytes, err := stub.GetState("Popcode:" + createArgs.Address)

		if err != nil {
			fmt.Println("Could not get Popcode State")
			return nil, errors.New("Could not get Popcode State")
		}
		popcode := Pop.Pop{}

		if len(popcodebytes) == 0 {
			addrBytes, err := hex.DecodeString(createArgs.Address)
			if err != nil {
				return nil, fmt.Errorf("Invalid popcode address %s ", createArgs.Address)
			}
			hasher := sha256.New()
			hasher.Write(counterseed)
			hasher.Write(addrBytes)
			hashedCounterSeed := []byte{}
			hashedCounterSeed = hasher.Sum(hashedCounterSeed)
			popcode.Counter = hashedCounterSeed[:]
			popcode.Address = hex.EncodeToString(addrBytes)

			err = popcode.CreateOutput(int(createArgs.Amount), createArgs.Type, createArgs.Data, createArgs.CreatorPubKey, createArgs.CreatorSig)
			if err != nil {
				fmt.Printf(err.Error())
				return nil, err
			}

			antiReplayDigest := sha256.Sum256(createArgs.CreatorSig) // WARNING Assumes the Creator sig is not malleable without private key. Need to check if all maleability vectors are checked

			if txCache.Cache[string(antiReplayDigest[:])] {
				fmt.Printf("Already recieved transaction")
				return nil, fmt.Errorf("Already recieved transaction")
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
				return nil, errors.New("Popcode Deserialization Failure")
			}
			err = popcode.CreateOutput(int(createArgs.Amount), createArgs.Type, createArgs.Data, createArgs.CreatorPubKey, createArgs.CreatorSig)
			if err != nil {
				fmt.Printf(err.Error())
				return nil, err
			}

		}

		sigHash := sha256.Sum256(createArgs.CreatorSig[:])
		cacheIndex := hex.EncodeToString(sigHash[:])
		txCache.Cache[cacheIndex] = true
		err = stub.PutState("Popcode:"+createArgs.Address, popcode.ToBytes())
		if err != nil {
			fmt.Printf(err.Error())
			return nil, err
		}

	case "transfer":
		transferArgs := TuxedoPopsTX.TransferOwners{}
		err = proto.Unmarshal(argsBytes, &transferArgs)
		if err != nil {
			fmt.Println("Invalid argument expected TransferOwners protocol buffer")
			return nil, fmt.Errorf("Invalid argument expected TransferOwners protocol buffer %s", err.Error())
		}
		popcodebytes, err := stub.GetState("Popcode:" + transferArgs.Address)
		if err != nil {
			fmt.Println("Could not get Popcode State")
			return nil, errors.New("Could not get Popcode State")
		}
		if len(popcodebytes) == 0 {
			fmt.Println("No value found in popcode")
			return nil, errors.New("No value found in popcode")
		}

		popcode := Pop.Pop{}
		popcode.FromBytes(popcodebytes)
		err = popcode.SetOwner(int(transferArgs.Output), int(transferArgs.Threshold), transferArgs.Data, transferArgs.Owners, transferArgs.PrevOwnerSigs, transferArgs.PopcodePubKey, transferArgs.PopcodeSig)
		if err != nil {
			fmt.Printf(err.Error())
			return nil, err
		}
		err = stub.PutState("Popcode:"+transferArgs.Address, popcode.ToBytes())
		if err != nil {
			fmt.Printf(err.Error())
			return nil, err
		}
	case "unitize":
		unitizeArgs := TuxedoPopsTX.Unitize{}
		err = proto.Unmarshal(argsBytes, &unitizeArgs)
		if err != nil {
			fmt.Println("Invalid argument expected Unitize protocol buffer")
			return nil, fmt.Errorf("Invalid argument expected Unitize protocol buffer %s", err.Error())
		}
		popcodeKeyDigest := sha256.Sum256(unitizeArgs.PopcodePubKey)
		sourceAddress := hex.EncodeToString(popcodeKeyDigest[:20])
		sourcePopcodeBytes, err := stub.GetState("Popcode:" + sourceAddress)
		if err != nil {
			fmt.Println("Could not get Popcode State")
			return nil, errors.New("Could not get Popcode State")
		}
		if len(sourcePopcodeBytes) == 0 {
			fmt.Println("No value found in popcode")
			return nil, errors.New("No value found in popcode")
		}
		sourcePopcode := Pop.Pop{}
		err = sourcePopcode.FromBytes(sourcePopcodeBytes)
		if err != nil {
			fmt.Println("Could not get Popcode State")
			return nil, errors.New("Could not get Popcode State")
		}
		destAddress := unitizeArgs.DestAddress
		destPopcodeBytes, err := stub.GetState("Popcode:" + destAddress)
		if err != nil {
			return nil, errors.New("Could not get Popcode State")
		}
		destPopcode := Pop.Pop{}
		if len(destPopcodeBytes) == 0 {
			destAddressBytes, err := hex.DecodeString(destAddress)
			if err != nil {
				return nil, fmt.Errorf("Invalid address %s", destAddress)
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
				return nil, errors.New("Dest Popcode Deserialization Failure")
			}
		}
		convertedAmounts := make([]int, len(unitizeArgs.DestAmounts))
		for i, destAmount := range unitizeArgs.DestAmounts {
			convertedAmounts[i] = int(destAmount)
		}
		sourcePopcode.UnitizeOutput(int(unitizeArgs.SourceOutput), convertedAmounts, unitizeArgs.Data, &destPopcode, unitizeArgs.OwnerSigs, unitizeArgs.PopcodePubKey, unitizeArgs.PopcodeSig)
		err = stub.PutState("Popcode:"+sourceAddress, sourcePopcode.ToBytes())
		if err != nil {
			fmt.Printf(err.Error())
			return nil, err
		}
		err = stub.PutState("Popcode:"+destAddress, destPopcode.ToBytes())
		if err != nil {
			fmt.Printf(err.Error())
			return nil, err
		}
	case "combine":
		combineArgs := TuxedoPopsTX.Combine{}

		err = proto.Unmarshal(argsBytes, &combineArgs)
		if err != nil {
			fmt.Println("Invalid argument expected Combine protocol buffer")
			return nil, fmt.Errorf("Invalid argument expected Combine protocol buffer %s", err.Error())
		}

		popcode := Pop.Pop{}
		popcodeBytes, err := stub.GetState("Popcode:" + combineArgs.Address)
		if err != nil {
			fmt.Println("Could not get Popcode State")
			return nil, errors.New("Could not get Popcode State")
		}
		if len(popcodeBytes) == 0 {
			fmt.Println("No value found in popcode")
			return nil, errors.New("No value found in popcode")
		}
		popcode.FromBytes(popcodeBytes)

		recipeBytes, err := stub.GetState("Recipe:" + combineArgs.Recipe)

		if err != nil {
			fmt.Println("Could not get Recipe State")
			return nil, errors.New("Could not get Recipe State")
		}
		if len(recipeBytes) == 0 {
			fmt.Printf("Recipe %s not registered", combineArgs.Recipe)
			return nil, fmt.Errorf("Recipe %s already registered", combineArgs.Recipe)
		}
		recipe := TuxedoPopsStore.Recipe{}
		err = proto.Unmarshal(recipeBytes, &recipe)
		if err != nil {
			return nil, fmt.Errorf("Could not deserialize Recipe %s", combineArgs.Recipe)
		}

		sources := make([]Pop.SourceOutput, len(combineArgs.Sources))

		for i, v := range combineArgs.Sources {
			sources[i] = v
		}

		popcode.CombineOutputs(sources, combineArgs.OwnerSigs, combineArgs.PopcodePubKey, combineArgs.PopcodeSigs, int(combineArgs.Amount), recipe, combineArgs.Data, combineArgs.CreatorPubKey, combineArgs.CreatorSig)
		err = stub.PutState("Popcode:"+combineArgs.Address, popcode.ToBytes())
		if err != nil {
			fmt.Printf(err.Error())
			return nil, err
		}

	case "recipe":
		recipeArgs := TuxedoPopsTX.Recipe{}
		err = proto.Unmarshal(argsBytes, &recipeArgs)
		if err != nil {
			fmt.Println("Invalid argument expected Recipe protocol buffer")
			return nil, fmt.Errorf("Invalid argument expected Recipe protocol buffer %s", err.Error())
		}
		recipeBytes, err := stub.GetState("Recipe:" + recipeArgs.RecipeName)
		if err != nil {
			fmt.Println("Could not get Recipe State")
			return nil, errors.New("Could not get Recipe State")
		}
		//if recipe already exists
		if len(recipeBytes) != 0 {
			fmt.Printf("Recipe %s already registered", recipeArgs.RecipeName)
			return nil, fmt.Errorf("Recipe %s already registered", recipeArgs.RecipeName)
		}

		creatorPubKey, err := btcec.ParsePubKey(recipeArgs.CreatorPubKey, btcec.S256())
		if err != nil {
			return nil, fmt.Errorf("Could not deserialize Creator Pub Key %v", recipeArgs.CreatorPubKey)
		}

		creatorSig, err := btcec.ParseDERSignature(recipeArgs.CreatorSig, btcec.S256())

		if err != nil {
			return nil, fmt.Errorf("Could not deserialize Creator Signature %v", recipeArgs.CreatorSig)
		}

		message := recipeArgs.RecipeName + ":" + recipeArgs.CreatedType
		for _, ingredient := range recipeArgs.Ingredients {
			message += ":" + strconv.FormatInt(int64(ingredient.Numerator), 10) + ":" +
				strconv.FormatInt(int64(ingredient.Denominator), 10) + ":" + ingredient.Type
		}
		messageBytes := sha256.Sum256([]byte(message))
		success := creatorSig.Verify(messageBytes[:], creatorPubKey)
		if !success {
			fmt.Printf("Invalid Creator Signature %+v", creatorSig)
			return nil, fmt.Errorf("Invalid Creator Signature %+v", creatorSig)
		}

		recStore := TuxedoPopsStore.Recipe{}
		recStore.CreatedType = recipeArgs.CreatedType
		recStore.Creator = recipeArgs.CreatorPubKey
		for _, ingredient := range recipeArgs.Ingredients {
			ingredientStore := TuxedoPopsStore.Ingedient{}
			ingredientStore.Numerator = int64(ingredient.Numerator)
			ingredientStore.Denominator = int64(ingredient.Denominator)
			ingredientStore.Type = ingredient.Type
			recStore.Ingrediants = append(recStore.Ingrediants, &ingredientStore)
		}
		recStoreBytes, err := proto.Marshal(&recStore)
		if err != nil {
			fmt.Printf("Recipe Store Serialization error")
			return nil, fmt.Errorf("Recipe Store Serialization Erropr")
		}
		err = stub.PutState("Recipe:"+recipeArgs.RecipeName, recStoreBytes)
		if err != nil {
			fmt.Printf(err.Error())
			return nil, err
		}
	default:
		fmt.Printf("Invalid function type")
		return nil, fmt.Errorf("Invalid function type")
	}
	txCacheBytes, err = proto.Marshal(&txCache)
	if err != nil {
		fmt.Printf(err.Error())
		return nil, err
	}
	err = stub.PutState("TxCache", txCacheBytes)
	if err != nil {
		fmt.Printf(err.Error())
		return nil, err
	}
	err = stub.PutState("CounterSeed", counterseed)
	if err != nil {
		fmt.Printf(err.Error())
		return nil, err
	}
	return nil, nil
}

func (t *tuxedoPopsChaincode) Query(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	fmt.Printf("function: %s", function)
	switch function {
	case "balance":
		if len(args) != 1 {
			return nil, fmt.Errorf("No argument specified")
		}
		counterseed, err := stub.GetState("CounterSeed")

		if err != nil {
			fmt.Printf(err.Error())
			return nil, err
		}

		address := args[0]
		popcode := Pop.Pop{}
		popcodeBytes, err := stub.GetState("Popcode:" + address)
		if err != nil {
			fmt.Printf(err.Error())
			return nil, err
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
			return popcode.ToJSON(), nil
		}
		popcode.FromBytes(popcodeBytes)
		return popcode.ToJSON(), nil
	}
	return nil, nil
}

func main() {
	err := shim.Start(new(tuxedoPopsChaincode))
	if err != nil {
		fmt.Printf("Error starting chaincode: %s\n", err)
	}
}
