// Copyright 2017-2018 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package dvm

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/ast"
	"strconv"
	"strings"

	"github.com/blang/semver/v4"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/rpc"
	"golang.org/x/crypto/sha3"
)

// this files defines  external functions which can be called in DVM
// for example to load and store data from the blockchain and other basic functions

// random number generator is the basis
// however, further investigation is needed if we would like to enable users to use pederson commitments
// they can be used like
// original SC developers delivers a pederson commitment to SC as external oracle
// after x users have played lottery, dev reveals the commitment using which the winner is finalised
// this needs more investigation
// also, more investigation is required to enable predetermined external oracles

type DVM_FUNCTION_PTR_UINT64 func(dvm *DVM_Interpreter, expr *ast.CallExpr) (handled bool, result uint64)
type DVM_FUNCTION_PTR_STRING func(dvm *DVM_Interpreter, expr *ast.CallExpr) (handled bool, result string)
type DVM_FUNCTION_PTR_ANY func(dvm *DVM_Interpreter, expr *ast.CallExpr) (handled bool, result interface{})

var func_table = map[string][]func_data{}

type func_data struct {
	Range       semver.Range
	ComputeCost int64
	StorageCost int64
	PtrU        DVM_FUNCTION_PTR_UINT64
	PtrS        DVM_FUNCTION_PTR_STRING
	Ptr         DVM_FUNCTION_PTR_ANY
}

func init() {
	func_table = map[string][]func_data{
		// System & Execution Control
		"panic":          {{Range: semver.MustParseRange(">=0.0.0"), ComputeCost: 10000, StorageCost: 0, PtrU: dvm_panic}},
		"update_sc_code": {{Range: semver.MustParseRange(">=0.0.0"), ComputeCost: 5000, StorageCost: 0, PtrU: dvm_update_sc_code}},
		"version":        {{Range: semver.MustParseRange(">=0.0.0"), ComputeCost: 1000, StorageCost: 0, PtrU: dvm_version}},

		// Blockchain Context & Identifiers
		"blid":            {{Range: semver.MustParseRange(">=0.0.0"), ComputeCost: 2000, StorageCost: 0, PtrS: dvm_blid}},
		"block_height":    {{Range: semver.MustParseRange(">=0.0.0"), ComputeCost: 2000, StorageCost: 0, PtrU: dvm_block_height}},
		"block_timestamp": {{Range: semver.MustParseRange(">=0.0.0"), ComputeCost: 2500, StorageCost: 0, PtrU: dvm_block_timestamp}},
		"dero":            {{Range: semver.MustParseRange(">=0.0.0"), ComputeCost: 10000, StorageCost: 0, PtrS: dvm_dero}},
		"scid":            {{Range: semver.MustParseRange(">=0.0.0"), ComputeCost: 2000, StorageCost: 0, PtrS: dvm_scid}},
		"signer":          {{Range: semver.MustParseRange(">=0.0.0"), ComputeCost: 5000, StorageCost: 0, PtrS: dvm_signer}},
		"txid":            {{Range: semver.MustParseRange(">=0.0.0"), ComputeCost: 2000, StorageCost: 0, PtrS: dvm_txid}},

		// Global Key-Value State Storage
		"delete": {{Range: semver.MustParseRange(">=0.0.0"), ComputeCost: 3000, StorageCost: 0, PtrU: dvm_delete}},
		"exists": {{Range: semver.MustParseRange(">=0.0.0"), ComputeCost: 5000, StorageCost: 0, PtrU: dvm_exists}},
		"load":   {{Range: semver.MustParseRange(">=0.0.0"), ComputeCost: 5000, StorageCost: 0, Ptr: dvm_load}},
		"store":  {{Range: semver.MustParseRange(">=0.0.0"), ComputeCost: 10000, StorageCost: 0, PtrU: dvm_store}},

		// Map State Storage
		"mapdelete": {{Range: semver.MustParseRange(">=0.0.0"), ComputeCost: 1000, StorageCost: 0, PtrU: dvm_mapdelete}},
		"mapexists": {{Range: semver.MustParseRange(">=0.0.0"), ComputeCost: 1000, StorageCost: 0, PtrU: dvm_mapexists}},
		"mapget":    {{Range: semver.MustParseRange(">=0.0.0"), ComputeCost: 1000, StorageCost: 0, Ptr: dvm_mapget}},
		"mapstore":  {{Range: semver.MustParseRange(">=0.0.0"), ComputeCost: 1000, StorageCost: 0, PtrU: dvm_mapstore}},

		// Asset Transacting & Address Management
		"address_raw":           {{Range: semver.MustParseRange(">=0.0.0"), ComputeCost: 60000, StorageCost: 0, PtrS: dvm_address_raw}},
		"address_string":        {{Range: semver.MustParseRange(">=0.0.0"), ComputeCost: 50000, StorageCost: 0, PtrS: dvm_address_string}},
		"assetvalue":            {{Range: semver.MustParseRange(">=0.0.0"), ComputeCost: 10000, StorageCost: 0, PtrU: dvm_assetvalue}},
		"derovalue":             {{Range: semver.MustParseRange(">=0.0.0"), ComputeCost: 10000, StorageCost: 0, PtrU: dvm_derovalue}},
		"is_address_valid":      {{Range: semver.MustParseRange(">=0.0.0"), ComputeCost: 50000, StorageCost: 0, PtrU: dvm_is_address_valid}},
		"send_asset_to_address": {{Range: semver.MustParseRange(">=0.0.0"), ComputeCost: 90000, StorageCost: 0, PtrU: dvm_send_asset_to_address}},
		"send_dero_to_address":  {{Range: semver.MustParseRange(">=0.0.0"), ComputeCost: 70000, StorageCost: 0, PtrU: dvm_send_dero_to_address}},

		// Cryptography & Randomness
		"keccak256": {{Range: semver.MustParseRange(">=0.0.0"), ComputeCost: 25000, StorageCost: 0, PtrS: dvm_keccak256}},
		"random":    {{Range: semver.MustParseRange(">=0.0.0"), ComputeCost: 2500, StorageCost: 0, PtrU: dvm_random}},
		"sha256":    {{Range: semver.MustParseRange(">=0.0.0"), ComputeCost: 25000, StorageCost: 0, PtrS: dvm_sha256}},
		"sha3256":   {{Range: semver.MustParseRange(">=0.0.0"), ComputeCost: 25000, StorageCost: 0, PtrS: dvm_sha3256}},

		// Math, String & Encoding Utilities
		"atoi":      {{Range: semver.MustParseRange(">=0.0.0"), ComputeCost: 5000, StorageCost: 0, PtrU: dvm_atoi}},
		"hex":       {{Range: semver.MustParseRange(">=0.0.0"), ComputeCost: 10000, StorageCost: 0, PtrS: dvm_hex}},
		"hexdecode": {{Range: semver.MustParseRange(">=0.0.0"), ComputeCost: 10000, StorageCost: 0, PtrS: dvm_hexdecode}},
		"itoa":      {{Range: semver.MustParseRange(">=0.0.0"), ComputeCost: 5000, StorageCost: 0, PtrS: dvm_itoa}},
		"max":       {{Range: semver.MustParseRange(">=0.0.0"), ComputeCost: 5000, StorageCost: 0, PtrU: dvm_max}},
		"min":       {{Range: semver.MustParseRange(">=0.0.0"), ComputeCost: 5000, StorageCost: 0, PtrU: dvm_min}},
		"strlen":    {{Range: semver.MustParseRange(">=0.0.0"), ComputeCost: 20000, StorageCost: 0, PtrU: dvm_strlen}},
		"substr":    {{Range: semver.MustParseRange(">=0.0.0"), ComputeCost: 20000, StorageCost: 0, PtrS: dvm_substr}},
		// Cross-Contract Calls (fork)
		"call_sc": {{Range: semver.MustParseRange(">=10.0.0"), ComputeCost: 10000, StorageCost: 0, PtrU: dvm_call_sc}},
	}
}

// this will handle all internal functions which may be required/necessary to expand DVM functionality
func (dvm *DVM_Interpreter) Handle_Internal_Function(expr *ast.CallExpr, func_name string) (handled bool, result interface{}) {

	if func_data_array, ok := func_table[strings.ToLower(func_name)]; ok {
		for _, f := range func_data_array {
			if f.Range(dvm.Version) {
				dvm.State.ConsumeGas(f.ComputeCost)
				if f.PtrU != nil {
					return f.PtrU(dvm, expr)
				} else if f.PtrS != nil {
					return f.PtrS(dvm, expr)
				} else {
					return f.Ptr(dvm, expr)
				}
			}
		}
		panic("function doesnot match any version")
	}
	//panic("function does not exist")
	return false, nil // function does not exist
}

// the load/store functions are sandboxed and thus cannot affect any other SC storage
// loads  a variable from store
func (dvm *DVM_Interpreter) Load(key Variable) interface{} {
	var found uint64
	result := dvm.State.Store.Load(DataKey{SCID: dvm.State.Chain_inputs.SCID, Key: key}, &found)

	switch result.Type {
	case Uint64:
		return result.ValueUint64
	case String:
		return result.ValueString

	default:
		panic("Unhandled data_type")
	}
}

// whether a variable exists in store or not
func (dvm *DVM_Interpreter) Exists(key Variable) uint64 {
	var found uint64
	dvm.State.Store.Load(DataKey{SCID: dvm.State.Chain_inputs.SCID, Key: key}, &found)
	return found
}

func (dvm *DVM_Interpreter) Store(key Variable, value Variable) {
	dvm.State.Store.Store(DataKey{SCID: dvm.State.Chain_inputs.SCID, Key: key}, value)
}

func (dvm *DVM_Interpreter) Delete(key Variable) {
	dvm.State.Store.Delete(DataKey{SCID: dvm.State.Chain_inputs.SCID, Key: key})
}

// we should migrate to generics ASAP
func convertdatatovariable(datai interface{}) Variable {
	switch k := datai.(type) {
	case uint64:
		return Variable{Type: Uint64, ValueUint64: k}
	case string:
		return Variable{Type: String, ValueString: k}
	default:
		panic("This variable cannot be loaded")
	}
}

// checks whether necessary number of arguments have been provided
func checkargscount(expected, actual int) {
	if expected != actual {
		panic("incorrect number of arguments")
	}
}

func dvm_version(dvm *DVM_Interpreter, expr *ast.CallExpr) (handled bool, result uint64) {
	checkargscount(1, len(expr.Args)) // check number of arguments

	if version_str, ok := dvm.eval(expr.Args[0]).(string); !ok {
		panic("unsupported version format")
	} else {
		dvm.Version = semver.MustParse(version_str)
	}
	return true, uint64(1)
}

func dvm_load(dvm *DVM_Interpreter, expr *ast.CallExpr) (handled bool, result interface{}) {
	checkargscount(1, len(expr.Args)) // check number of arguments
	key := dvm.eval(expr.Args[0])
	return true, dvm.Load(convertdatatovariable(key))

}

func dvm_exists(dvm *DVM_Interpreter, expr *ast.CallExpr) (handled bool, result uint64) {
	checkargscount(1, len(expr.Args)) // check number of arguments
	key := dvm.eval(expr.Args[0])     // evaluate the argument and use the result
	return true, dvm.Exists(convertdatatovariable(key))
}

func dvm_store(dvm *DVM_Interpreter, expr *ast.CallExpr) (handled bool, result uint64) {
	checkargscount(2, len(expr.Args)) // check number of arguments
	key := convertdatatovariable(dvm.eval(expr.Args[0]))
	value := convertdatatovariable(dvm.eval(expr.Args[1]))

	dvm.Store(key, value)
	return true, 1
}

func dvm_delete(dvm *DVM_Interpreter, expr *ast.CallExpr) (handled bool, result uint64) {
	checkargscount(1, len(expr.Args)) // check number of arguments
	key := convertdatatovariable(dvm.eval(expr.Args[0]))
	dvm.Delete(key)
	return true, uint64(1)
}

func dvm_mapexists(dvm *DVM_Interpreter, expr *ast.CallExpr) (handled bool, result uint64) {
	checkargscount(1, len(expr.Args))                    // check number of arguments
	key := convertdatatovariable(dvm.eval(expr.Args[0])) // evaluate the argument and use the result

	if _, ok := dvm.State.RamStore[key]; ok {
		return true, uint64(1)
	}
	return true, uint64(0)

}

func dvm_mapget(dvm *DVM_Interpreter, expr *ast.CallExpr) (handled bool, result interface{}) {
	checkargscount(1, len(expr.Args))                    // check number of arguments
	key := convertdatatovariable(dvm.eval(expr.Args[0])) // evaluate the argument and use the result

	v := dvm.State.RamStore[key]

	if v.Type == Uint64 {
		return true, v.ValueUint64
	} else if v.Type == String {
		return true, v.ValueString
	} else {
		panic("This variable cannot be obtained")
	}
}

func dvm_mapstore(dvm *DVM_Interpreter, expr *ast.CallExpr) (handled bool, result uint64) {
	checkargscount(2, len(expr.Args))                      // check number of arguments
	key := convertdatatovariable(dvm.eval(expr.Args[0]))   // evaluate the argument and use the result
	value := convertdatatovariable(dvm.eval(expr.Args[1])) // evaluate the argument and use the result

	dvm.State.RamStore[key] = value
	return true, uint64(1)
}

func dvm_mapdelete(dvm *DVM_Interpreter, expr *ast.CallExpr) (handled bool, result uint64) {
	checkargscount(1, len(expr.Args))                    // check number of arguments
	key := convertdatatovariable(dvm.eval(expr.Args[0])) // evaluate the argument and use the result

	delete(dvm.State.RamStore, key)
	return true, uint64(1)
}

func dvm_random(dvm *DVM_Interpreter, expr *ast.CallExpr) (handled bool, result uint64) {
	if len(expr.Args) >= 2 {
		panic("RANDOM function expects 0 or 1 number as parameter")
	}

	if len(expr.Args) == 0 { // expression without limit
		return true, dvm.State.RND.Random()
	}

	range_eval := dvm.eval(expr.Args[0])
	switch k := range_eval.(type) {
	case uint64:
		return true, dvm.State.RND.Random_MAX(k)
	default:
		panic("This variable cannot be randomly generated")
	}
}

func dvm_scid(dvm *DVM_Interpreter, expr *ast.CallExpr) (handled bool, result string) {
	checkargscount(0, len(expr.Args)) // check number of arguments
	return true, string(dvm.State.Chain_inputs.SCID[:])
}
func dvm_blid(dvm *DVM_Interpreter, expr *ast.CallExpr) (handled bool, result string) {
	checkargscount(0, len(expr.Args)) // check number of arguments
	return true, string(dvm.State.Chain_inputs.BLID[:])
}
func dvm_txid(dvm *DVM_Interpreter, expr *ast.CallExpr) (handled bool, result string) {
	checkargscount(0, len(expr.Args)) // check number of arguments
	return true, string(dvm.State.Chain_inputs.TXID[:])
}

func dvm_dero(dvm *DVM_Interpreter, expr *ast.CallExpr) (handled bool, result string) {
	checkargscount(0, len(expr.Args)) // check number of arguments
	var zerohash crypto.Hash
	return true, string(zerohash[:])
}
func dvm_block_height(dvm *DVM_Interpreter, expr *ast.CallExpr) (handled bool, result uint64) {
	checkargscount(0, len(expr.Args)) // check number of arguments
	return true, dvm.State.Chain_inputs.BL_HEIGHT
}

/*
	func dvm_block_topoheight(dvm *DVM_Interpreter, expr *ast.CallExpr)(handled bool, result interface{}){
		if len(expr.Args) != 0 {
				panic("BLOCK_HEIGHT function expects 0 parameters")
			}
			return true, dvm.State.Chain_inputs.BL_TOPOHEIGHT
	}
*/
func dvm_block_timestamp(dvm *DVM_Interpreter, expr *ast.CallExpr) (handled bool, result uint64) {
	checkargscount(0, len(expr.Args)) // check number of arguments
	return true, dvm.State.Chain_inputs.BL_TIMESTAMP
}

func dvm_signer(dvm *DVM_Interpreter, expr *ast.CallExpr) (handled bool, result string) {
	checkargscount(0, len(expr.Args)) // check number of arguments
	return true, dvm.State.Chain_inputs.Signer
}

func dvm_update_sc_code(dvm *DVM_Interpreter, expr *ast.CallExpr) (handled bool, result uint64) {
	checkargscount(1, len(expr.Args)) // check number of arguments
	code_eval := dvm.eval(expr.Args[0])
	switch k := code_eval.(type) {
	case string:
		dvm.State.Store.Store(DataKey{Key: Variable{Type: String, ValueString: "C"}}, Variable{Type: String, ValueString: k}) // TODO verify code authenticity how
		return true, uint64(1)
	default:
		return true, uint64(0)
	}
}

func dvm_is_address_valid(dvm *DVM_Interpreter, expr *ast.CallExpr) (handled bool, result uint64) {
	checkargscount(1, len(expr.Args)) // check number of arguments

	addr_eval := dvm.eval(expr.Args[0])
	switch k := addr_eval.(type) {
	case string:

		addr_raw := new(crypto.Point)
		if err := addr_raw.DecodeCompressed([]byte(k)); err == nil {
			return true, uint64(1)
		}
		return true, uint64(0) // fallthrough not supported in type switch

	default:
		return true, uint64(0)
	}
}

func dvm_address_raw(dvm *DVM_Interpreter, expr *ast.CallExpr) (handled bool, result string) {
	checkargscount(1, len(expr.Args)) // check number of arguments

	addr_eval := dvm.eval(expr.Args[0])
	switch k := addr_eval.(type) {
	case string:
		if addr, err := rpc.NewAddress(k); err == nil {
			return true, string(addr.Compressed())
		}

		return true, "" // fallthrough not supported in type switch
	default:
		return true, ""
	}
}

func dvm_address_string(dvm *DVM_Interpreter, expr *ast.CallExpr) (handled bool, result string) {
	checkargscount(1, len(expr.Args)) // check number of arguments

	addr_eval := dvm.eval(expr.Args[0])
	switch k := addr_eval.(type) {
	case string:
		p := new(crypto.Point)
		if err := p.DecodeCompressed([]byte(k)); err == nil {

			addr := rpc.NewAddressFromKeys(p)
			return true, addr.String()
		}

		return true, "" // fallthrough not supported in type switch
	default:
		return true, ""
	}
}

func dvm_send_dero_to_address(dvm *DVM_Interpreter, expr *ast.CallExpr) (handled bool, result uint64) {
	checkargscount(2, len(expr.Args)) // check number of arguments

	addr_eval := dvm.eval(expr.Args[0])
	amount_eval := dvm.eval(expr.Args[1])

	if err := new(crypto.Point).DecodeCompressed([]byte(addr_eval.(string))); err != nil {
		panic("address must be valid DERO network address")
	}

	if _, ok := amount_eval.(uint64); !ok {
		panic("amount must be valid  uint64")
	}

	if amount_eval.(uint64) == 0 {
		return true, amount_eval.(uint64)
	}
	var zerohash crypto.Hash
	dvm.State.Store.SendExternal(dvm.State.Chain_inputs.SCID, zerohash, addr_eval.(string), amount_eval.(uint64)) // add record for external transfer
	return true, amount_eval.(uint64)
}
func dvm_send_asset_to_address(dvm *DVM_Interpreter, expr *ast.CallExpr) (handled bool, result uint64) {
	checkargscount(3, len(expr.Args)) // check number of arguments

	addr_eval := dvm.eval(expr.Args[0])
	amount_eval := dvm.eval(expr.Args[1])
	asset_eval := dvm.eval(expr.Args[2])

	if err := new(crypto.Point).DecodeCompressed([]byte(addr_eval.(string))); err != nil {
		panic("address must be valid DERO network address")
	}

	if _, ok := amount_eval.(uint64); !ok {
		panic("amount must be valid  uint64")
	}

	if _, ok := asset_eval.(string); !ok {
		panic("asset must be valid string")
	}

	//fmt.Printf("sending asset %x (%d) to address %x\n", asset_eval.(string), amount_eval.(uint64),[]byte(addr_eval.(string)))

	if amount_eval.(uint64) == 0 {
		return true, amount_eval.(uint64)
	}

	if len(asset_eval.(string)) != 32 {
		panic("asset must be valid string of 32 byte length")
	}
	var asset crypto.Hash
	copy(asset[:], ([]byte(asset_eval.(string))))

	dvm.State.Store.SendExternal(dvm.State.Chain_inputs.SCID, asset, addr_eval.(string), amount_eval.(uint64)) // add record for external transfer

	return true, amount_eval.(uint64)
}

func dvm_derovalue(dvm *DVM_Interpreter, expr *ast.CallExpr) (handled bool, result uint64) {
	checkargscount(0, len(expr.Args)) // check number of arguments
	return true, dvm.State.Assets[dvm.State.SCIDZERO]

}

func dvm_assetvalue(dvm *DVM_Interpreter, expr *ast.CallExpr) (handled bool, result uint64) {
	checkargscount(1, len(expr.Args)) // check number of arguments

	asset_eval := dvm.eval(expr.Args[0])

	if _, ok := asset_eval.(string); !ok {
		panic("asset must be valid string")
	}
	if len(asset_eval.(string)) != 32 {
		panic("asset must be valid string of 32 byte length")
	}
	var asset crypto.Hash
	copy(asset[:], ([]byte(asset_eval.(string))))

	return true, dvm.State.Assets[asset]

}

func dvm_itoa(dvm *DVM_Interpreter, expr *ast.CallExpr) (handled bool, result string) {
	checkargscount(1, len(expr.Args)) // check number of arguments

	asset_eval := dvm.eval(expr.Args[0])

	if _, ok := asset_eval.(uint64); !ok {
		panic("itoa argument must be valid uint64")
	}

	return true, fmt.Sprintf("%d", asset_eval.(uint64))

}

func dvm_atoi(dvm *DVM_Interpreter, expr *ast.CallExpr) (handled bool, result uint64) {
	checkargscount(1, len(expr.Args)) // check number of arguments

	asset_eval := dvm.eval(expr.Args[0])

	if _, ok := asset_eval.(string); !ok {
		panic("atoi argument must be valid string")
	}

	if u, err := strconv.ParseUint(asset_eval.(string), 10, 64); err != nil {
		panic(err)
	} else {
		return true, u
	}

}

func dvm_strlen(dvm *DVM_Interpreter, expr *ast.CallExpr) (handled bool, result uint64) {
	checkargscount(1, len(expr.Args)) // check number of arguments
	asset_eval := dvm.eval(expr.Args[0])

	if _, ok := asset_eval.(string); !ok {
		panic("atoi argument must be valid string")
	}
	return true, uint64(len([]byte(asset_eval.(string))))

}

func substr(input string, start uint64, length uint64) string {
	asbytes := []byte(input)

	if start >= uint64(len(asbytes)) {
		return ""
	}

	if start+length > uint64(len(asbytes)) {
		length = uint64(len(asbytes)) - start
	}

	return string(asbytes[start : start+length])
}

func dvm_substr(dvm *DVM_Interpreter, expr *ast.CallExpr) (handled bool, result string) {
	checkargscount(3, len(expr.Args)) // check number of arguments
	input_eval := dvm.eval(expr.Args[0])
	if _, ok := input_eval.(string); !ok {
		panic("input argument must be valid string")
	}
	offset_eval := dvm.eval(expr.Args[1])
	if _, ok := offset_eval.(uint64); !ok {
		panic("input argument must be valid uint64")
	}
	length_eval := dvm.eval(expr.Args[2])
	if _, ok := length_eval.(uint64); !ok {
		panic("input argument must be valid uint64")
	}

	return true, substr(input_eval.(string), offset_eval.(uint64), length_eval.(uint64))
}

func dvm_sha256(dvm *DVM_Interpreter, expr *ast.CallExpr) (handled bool, result string) {
	checkargscount(1, len(expr.Args)) // check number of arguments
	input_eval := dvm.eval(expr.Args[0])
	if _, ok := input_eval.(string); !ok {
		panic("input argument must be valid string")
	}

	hash := sha256.Sum256([]byte(input_eval.(string)))
	return true, string(hash[:])
}

func dvm_sha3256(dvm *DVM_Interpreter, expr *ast.CallExpr) (handled bool, result string) {
	checkargscount(1, len(expr.Args)) // check number of arguments
	input_eval := dvm.eval(expr.Args[0])
	if _, ok := input_eval.(string); !ok {
		panic("input argument must be valid string")
	}

	hash := sha3.Sum256([]byte(input_eval.(string)))
	return true, string(hash[:])
}

func dvm_keccak256(dvm *DVM_Interpreter, expr *ast.CallExpr) (handled bool, result string) {
	checkargscount(1, len(expr.Args)) // check number of arguments
	input_eval := dvm.eval(expr.Args[0])
	if _, ok := input_eval.(string); !ok {
		panic("input argument must be valid string")
	}

	h1 := sha3.NewLegacyKeccak256()
	h1.Write([]byte(input_eval.(string)))
	hash := h1.Sum(nil)
	return true, string(hash[:])
}

func dvm_hex(dvm *DVM_Interpreter, expr *ast.CallExpr) (handled bool, result string) {
	checkargscount(1, len(expr.Args)) // check number of arguments
	input_eval := dvm.eval(expr.Args[0])
	if _, ok := input_eval.(string); !ok {
		panic("input argument must be valid string")
	}
	return true, hex.EncodeToString([]byte(input_eval.(string)))
}
func dvm_hexdecode(dvm *DVM_Interpreter, expr *ast.CallExpr) (handled bool, result string) {
	checkargscount(1, len(expr.Args)) // check number of arguments
	input_eval := dvm.eval(expr.Args[0])
	if _, ok := input_eval.(string); !ok {
		panic("input argument must be valid string")
	}

	if b, err := hex.DecodeString(input_eval.(string)); err != nil {
		panic(err)
	} else {
		return true, string(b)
	}
}

func dvm_min(dvm *DVM_Interpreter, expr *ast.CallExpr) (handled bool, result uint64) {
	checkargscount(2, len(expr.Args)) // check number of arguments

	a1 := dvm.eval(expr.Args[0])
	if _, ok := a1.(uint64); !ok {
		panic("input argument must be uint64")
	}

	a2 := dvm.eval(expr.Args[1])
	if _, ok := a1.(uint64); !ok {
		panic("input argument must be uint64")
	}

	if a1.(uint64) < a2.(uint64) {
		return true, a1.(uint64)
	}
	return true, a2.(uint64)
}

func dvm_max(dvm *DVM_Interpreter, expr *ast.CallExpr) (handled bool, result uint64) {
	checkargscount(2, len(expr.Args)) // check number of arguments
	a1 := dvm.eval(expr.Args[0])
	if _, ok := a1.(uint64); !ok {
		panic("input argument must be uint64")
	}

	a2 := dvm.eval(expr.Args[1])
	if _, ok := a1.(uint64); !ok {
		panic("input argument must be uint64")
	}

	if a1.(uint64) > a2.(uint64) {
		return true, a1.(uint64)
	}
	return true, a2.(uint64)
}

func dvm_panic(dvm *DVM_Interpreter, expr *ast.CallExpr) (handled bool, result uint64) {
	panic("panic function called")
	return true, uint64(0)
}

func dvm_call_sc(dvm *DVM_Interpreter, expr *ast.CallExpr) (handled bool, result uint64) {
	// args: scid, entrypoint, then name/value pairs (even count after idx 2)
	if len(expr.Args) < 2 || (len(expr.Args)-2)%2 != 0 {
		panic("call_sc: expected scid, entrypoint, then name/value pairs")
	}
	scid_hex, ok := dvm.eval(expr.Args[0]).(string)
	if !ok {
		panic("call_sc: scid must be a hex string")
	}
	entrypoint, ok := dvm.eval(expr.Args[1]).(string)
	if !ok {
		panic("call_sc: entrypoint must be a string")
	}

	var target crypto.Hash
	// The fork's simulator addresses SCs by their hex-string form; accept
	// the target as raw 32 bytes (DataHash path) OR proper 64-char hex.
	if len(scid_hex) == 32 {
		copy(target[:], []byte(scid_hex))
	} else if scid_bytes, err := hex.DecodeString(scid_hex); err == nil && len(scid_bytes) == 32 {
		copy(target[:], scid_bytes)
	} else {
		return true, uint64(2)
	}

	// recursion cap: 8 nested levels
	if dvm.State.Monitor_recursion >= 8 {
		return true, uint64(2) // recursion depth exceeded — fail cleanly
	}
	if dvm.State.DataTree == nil {
		return true, uint64(3) // no data tree (unit-test context) — fail cleanly
	}

	// resolve the target SC from ITS OWN tree (each SC's code lives in its
	// per-SCID tree; the caller's DataTree only wraps the caller)
	var targetTree *Tree_Wrapper
	if dvm.State.Snapshot != nil {
		targetTree = Wrapped_tree(dvm.State.TreeCache, dvm.State.Snapshot, target)
	} else if dvm.State.DataTree != nil {
		targetTree = dvm.State.DataTree // fallback: shared tree (unit tests)
	} else {
		return true, uint64(3)
	}
	_, targetSC, found := ReadSC(nil, targetTree, target)
	if !found {
		return true, uint64(4) // target not found
	}
	if _, ok := targetSC.Functions[entrypoint]; !ok {
		return true, uint64(5) // entrypoint not found
	}

	// build the callee's params from the name/value pairs.
	// Reserved names "value" / "assetvalue" / "asset" forward incoming
	// funds: the callee sees DEROVALUE()/ASSETVALUE() == the forwarded
	// amount; the caller leftover is reduced on success.
	params := map[string]interface{}{}
	var fwdDERO uint64
	var fwdAsset crypto.Hash
	var fwdAssetAmt uint64
	haveAsset := false
	for i := 2; i+1 < len(expr.Args); i += 2 {
		name, ok := dvm.eval(expr.Args[i]).(string)
		if !ok {
			return true, uint64(2)
		}
		val := dvm.eval(expr.Args[i+1])
		switch strings.ToLower(name) {
		case "value":
			n, ok := callScAsUint64(val)
			if !ok {
				return true, uint64(2)
			}
			fwdDERO = n
			params[name] = fmt.Sprintf("%d", fwdDERO)
		case "assetvalue":
			n, ok := callScAsUint64(val)
			if !ok {
				return true, uint64(2)
			}
			fwdAssetAmt = n
			params[name] = fmt.Sprintf("%d", fwdAssetAmt)
		case "asset":
			as, ok := val.(string)
			if !ok {
				return true, uint64(2)
			}
			if len(as) == 32 {
				copy(fwdAsset[:], []byte(as))
			} else if b, err := hex.DecodeString(as); err == nil && len(b) == 32 {
				copy(fwdAsset[:], b)
			} else {
				return true, uint64(2)
			}
			haveAsset = true
			params[name] = as
		default:
			switch v := val.(type) {
			case uint64:
				params[name] = fmt.Sprintf("%d", v)
			case int64:
				params[name] = fmt.Sprintf("%d", v)
			case string:
				params[name] = v
			default:
				return true, uint64(2)
			}
		}
	}

	// snapshot for rollback on failure
	state := dvm.State
	snapAssets := make(map[crypto.Hash]uint64, len(state.Assets))
	for k, v := range state.Assets {
		snapAssets[k] = v
	}
	snapRawKeys := make(map[string][]byte, len(state.Store.RawKeys))
	for k, v := range state.Store.RawKeys {
		snapRawKeys[k] = v
	}
	snapTransfers := make(map[crypto.Hash]SC_Transfers, len(state.Store.Transfers))
	for k, v := range state.Store.Transfers {
		snapTransfers[k] = v
	}
	snapAssetsTransfer := make(map[string]map[string]uint64, len(state.Assets_Transfer))
	for k, v := range state.Assets_Transfer {
		cp := make(map[string]uint64, len(v))
		for kk, vv := range v {
			cp[kk] = vv
		}
		snapAssetsTransfer[k] = cp
	}
	snapSCIDSELF := state.SCIDSELF
	snapChainSCID := state.Chain_inputs.SCID
	snapStore := state.Store

	if fwdDERO > 0 && state.Assets[state.SCIDZERO] < fwdDERO {
		return true, uint64(2)
	}
	if haveAsset && fwdAssetAmt > 0 && state.Assets[fwdAsset] < fwdAssetAmt {
		return true, uint64(2)
	}

	// switch SCIDSELF AND Chain_inputs.SCID to the target for the nested
	// call (LOAD/STORE route by Chain_inputs.SCID; SCIDSELF is the address)
	state.SCIDSELF = target
	state.Chain_inputs.SCID = target

	// callee sees ONLY the forwarded incoming value (not the caller's pot)
	if fwdDERO > 0 || haveAsset {
		state.Assets = map[crypto.Hash]uint64{}
		if fwdDERO > 0 {
			state.Assets[state.SCIDZERO] = fwdDERO
		}
		if haveAsset && fwdAssetAmt > 0 {
			state.Assets[fwdAsset] = fwdAssetAmt
		}
	}

	// build a target-bound store so the nested LOAD/STORE reads/writes the
	// TARGET's tree (the caller's Store DiskLoader wraps the caller tree)
	if state.Snapshot != nil {
		targetTree = Wrapped_tree(state.TreeCache, state.Snapshot, target)
		nestedStore := Initialize_TX_store()
		nestedStore.SCID = target
		nestedStore.State = state
		nestedStore.DiskLoader = func(key DataKey, found *uint64) (result Variable) {
			var exists bool
			if result, exists = LoadSCValue(targetTree, key.SCID, key.MarshalBinaryPanic()); exists {
				*found = uint64(1)
			}
			return
		}
		nestedStore.BalanceLoader = func(key DataKey) uint64 {
			result, _ := LoadSCAssetValue(targetTree, key.SCID, key.Asset)
			return result
		}
		nestedStore.DiskLoaderRaw = func(key []byte) (value []byte, found bool) {
			var err error
			value, err = targetTree.Get(key[:])
			if err != nil {
				return nil, false
			}
			return value, true
		}
		state.Store = nestedStore
	}

	// run the nested entrypoint (shares state; bumps Monitor_recursion)
	nestedResult, runErr := runSmartContract_internal(&targetSC, entrypoint, state, params)
	// a nonzero RETURN is the callee's failure convention (0 = success),
	// so it must roll back exactly like an execution error
	if runErr != nil || nestedResult.Type != Uint64 || nestedResult.ValueUint64 != 0 {
		// rollback the nested call's writes
		state.Store = snapStore
		state.Store.RawKeys = snapRawKeys
		state.Store.Transfers = snapTransfers
		state.Assets_Transfer = snapAssetsTransfer
		state.Assets = snapAssets
		state.SCIDSELF = snapSCIDSELF
		state.Chain_inputs.SCID = snapChainSCID
		return true, uint64(2)
	}

	// surface the callee's return (0 = success). Commit the nested call's
	// writes directly to the TARGET's graviton tree — the top-level
	// deferred-commit loop only flushes the CALLER's tree wrapper, but the
	// target lives in its own per-SCID tree. Safe under the snapshot:
	// a failing top-level tx rolls the snapshot back.
	if targetTree != nil {
		for k, v := range state.Store.RawKeys {
			if len(v) > 0 {
				targetTree.Tree.Put([]byte(k), v)
			} else {
				targetTree.Tree.Delete([]byte(k))
			}
		}
	}
	state.SCIDSELF = snapSCIDSELF
	state.Chain_inputs.SCID = snapChainSCID
	state.Store = snapStore
	if fwdDERO > 0 || (haveAsset && fwdAssetAmt > 0) {
		restored := make(map[crypto.Hash]uint64, len(snapAssets))
		for k, v := range snapAssets {
			restored[k] = v
		}
		if fwdDERO > 0 {
			restored[state.SCIDZERO] -= fwdDERO
		}
		if haveAsset && fwdAssetAmt > 0 {
			restored[fwdAsset] -= fwdAssetAmt
		}
		state.Assets = restored
	}

	if nestedResult.Type == Uint64 {
		return true, nestedResult.ValueUint64
	}
	return true, uint64(2)
}

func callScAsUint64(val interface{}) (uint64, bool) {
	switch v := val.(type) {
	case uint64:
		return v, true
	case int64:
		if v < 0 {
			return 0, false
		}
		return uint64(v), true
	case string:
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return 0, false
		}
		return n, true
	default:
		return 0, false
	}
}
