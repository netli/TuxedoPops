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

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/core/chaincode/shim"
	"github.com/skuchain/popcodes_utxo/PopcodesTX"
	txcache "github.com/skuchain/popcodes_utxo/TXCache"
	"github.com/skuchain/popcodes_utxo/popcodes"
)

// This chaincode implements the ledger operations for the proofchaincode

// ProofChainCode example simple Chaincode implementation
type popcodesChaincode struct {
}

func (t *popcodesChaincode) Init(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
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

func (t *popcodesChaincode) Invoke(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
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
	}

	switch function {
	case "create":
		createArgs := popcodesTX.CreateTX{}
		err = proto.Unmarshal(argsBytes, &createArgs)
		if err != nil {
			fmt.Println("Invalid argument expected CreateTX protocol buffer")
			return nil, errors.New("Invalid argument expected CreateTX protocol buffer")
		}
		popcodeAddress := hex.EncodeToString(createArgs.Address)
		popcodebytes, err := stub.GetState(popcodeAddress)

		if err != nil {
			fmt.Println("Could not get Popcode State")
			return nil, errors.New("Could not get Popcode State")
		}
		popcode := popcodes.Popcode{}

		if len(popcodebytes) == 0 {
			hasher := sha256.New()
			hasher.Write(counterseed)
			hasher.Write(createArgs.Address)
			hashedCounterSeed := []byte{}
			hashedCounterSeed = hasher.Sum(hashedCounterSeed)
			popcode.Counter = hashedCounterSeed[:]
			popcode.Address = hex.EncodeToString(createArgs.Address)
			err = popcode.CreateOutput(int(createArgs.Amount), createArgs.Data, createArgs.CreatorPubKey, createArgs.CreatorSig)
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
			err = popcode.CreateOutput(int(createArgs.Amount), createArgs.Data, createArgs.CreatorPubKey, createArgs.CreatorSig)
			if err != nil {
				fmt.Printf(err.Error())
				return nil, err
			}

		}
		err = stub.PutState(popcodeAddress, popcode.ToBytes())
		if err != nil {
			fmt.Printf(err.Error())
			return nil, err
		}
	case "transfer":
		transferArgs := popcodesTX.TransferOwners{}
		err = proto.Unmarshal(argsBytes, &transferArgs)
		if err != nil {
			fmt.Println("Invalid argument expected TransferOwners protocol buffer")
			return nil, errors.New("Invalid argument expected TransferOwners protocol buffer")
		}
		popcodebytes, err := stub.GetState(transferArgs.Address)
		if err != nil {
			fmt.Println("Could not get Popcode State")
			return nil, errors.New("Could not get Popcode State")
		}
		if len(popcodebytes) == 0 {
			fmt.Println("No value found in popcode")
			return nil, errors.New("No value found in popcode")
		}

		popcode := popcodes.Popcode{}
		popcode.FromBytes(popcodebytes)
		err = popcode.SetOwner(int(transferArgs.Output), int(transferArgs.Threshold), transferArgs.Owners, transferArgs.PrevOwnerSigs, transferArgs.PopcodePubKey, transferArgs.PopcodeSig)
		if err != nil {
			fmt.Printf(err.Error())
			return nil, err
		}
		err = stub.PutState(transferArgs.Address, popcode.ToBytes())
		if err != nil {
			fmt.Printf(err.Error())
			return nil, err
		}
	case "unitize":
		unitizeArgs := popcodesTX.Unitize{}
		err = proto.Unmarshal(argsBytes, &unitizeArgs)
		if err != nil {
			fmt.Println("Invalid argument expected Unitize protocol buffer")
			return nil, errors.New("Invalid argument expected Unitize protocol buffer")
		}
		popcodeKeyDigest := sha256.Sum256(unitizeArgs.PopcodePubKey)
		sourceAddress := hex.EncodeToString(popcodeKeyDigest[:20])
		sourcePopcodeBytes, err := stub.GetState(sourceAddress)
		if err != nil {
			fmt.Println("Could not get Popcode State")
			return nil, errors.New("Could not get Popcode State")
		}
		if len(sourcePopcodeBytes) == 0 {
			fmt.Println("No value found in popcode")
			return nil, errors.New("No value found in popcode")
		}
		sourcePopcode := popcodes.Popcode{}
		err = sourcePopcode.FromBytes(sourcePopcodeBytes)
		if err != nil {
			fmt.Println("Could not get Popcode State")
			return nil, errors.New("Could not get Popcode State")
		}
		destAddress := hex.EncodeToString(unitizeArgs.DestAddress)
		destPopcodeBytes, err := stub.GetState(destAddress)
		if err != nil {
			fmt.Println("Could not get Popcode State")
			return nil, errors.New("Could not get Popcode State")
		}
		destPopcode := popcodes.Popcode{}
		if len(destPopcodeBytes) == 0 {
			hasher := sha256.New()
			hasher.Write(sourcePopcode.Counter)
			hasher.Write(unitizeArgs.DestAddress)
			hashedCounterSeed := []byte{}
			hashedCounterSeed = hasher.Sum(hashedCounterSeed)

			destPopcode.Counter = hashedCounterSeed[:]
		}
		convertedAmounts := make([]int, len(unitizeArgs.DestAmounts))
		for destAmount := range unitizeArgs.DestAmounts {
			convertedAmounts = append(convertedAmounts, int(destAmount))
		}
		sourcePopcode.UnitizeOutput(int(unitizeArgs.SourceOutput), convertedAmounts, &destPopcode, unitizeArgs.OwnerSigs, unitizeArgs.PopcodePubKey, unitizeArgs.PopcodeSig)
		err = stub.PutState(sourceAddress, sourcePopcode.ToBytes())
		if err != nil {
			fmt.Printf(err.Error())
			return nil, err
		}
		err = stub.PutState(destAddress, destPopcode.ToBytes())
		if err != nil {
			fmt.Printf(err.Error())
			return nil, err
		}
	case "combine":
		combineArgs := popcodesTX.Combine{}

		err = proto.Unmarshal(argsBytes, &combineArgs)
		if err != nil {
			fmt.Println("Invalid argument expected Combine protocol buffer")
			return nil, errors.New("Invalid argument expected Combine protocol buffer")
		}

		popcode := popcodes.Popcode{}
		popcodeBytes, err := stub.GetState(combineArgs.Address)
		if err != nil {
			fmt.Println("Could not get Popcode State")
			return nil, errors.New("Could not get Popcode State")
		}
		if len(popcodeBytes) == 0 {
			fmt.Println("No value found in popcode")
			return nil, errors.New("No value found in popcode")
		}
		popcode.FromBytes(popcodeBytes)

		sources := make([]popcodes.SourceOutput, len(combineArgs.Sources))

		for i, v := range combineArgs.Sources {
			sources[i] = v
		}

		popcode.CombineOutputs(sources, combineArgs.OwnerSigs, combineArgs.PopcodePubKey, combineArgs.PopcodeSigs, int(combineArgs.Amount), combineArgs.Data, combineArgs.CreatorPubKey, combineArgs.CreatorSig)
		err = stub.PutState(combineArgs.Address, popcode.ToBytes())
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

func (t *popcodesChaincode) Query(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {

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
		popcode := popcodes.Popcode{}
		popcodeBytes, err := stub.GetState(address)
		if err != nil {
			fmt.Printf(err.Error())
			return nil, err
		}
		if len(popcodeBytes) == 0 {
			popcode.Address = args[0]
			popcode.Counter = counterseed
			return popcode.ToJSON(), nil
		}
		popcode.FromBytes(popcodeBytes)
		return popcode.ToJSON(), nil

	}

	return nil, nil
}

func main() {
	err := shim.Start(new(popcodesChaincode))
	if err != nil {
		fmt.Printf("Error starting chaincode: %s\n", err)
	}
}
