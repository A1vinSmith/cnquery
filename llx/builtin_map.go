package llx

import (
	"errors"
	"strconv"
	"strings"

	"go.mondoo.io/mondoo/types"
)

// mapFunctions are all the handlers for builtin array methods
var mapFunctions map[string]chunkHandler

func mapGetIndex(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	if bind.Value == nil {
		return &RawData{Type: bind.Type.Child()}, 0, nil
	}

	args := chunk.Function.Args

	// TODO: all this needs to go into the compile phase
	if len(args) < 1 {
		return nil, 0, errors.New("Called [] with " + strconv.Itoa(len(args)) + " arguments, only 1 supported.")
	}
	if len(args) > 1 {
		return nil, 0, errors.New("Called [] with " + strconv.Itoa(len(args)) + " arguments, only 1 supported.")
	}
	t := types.Type(args[0].Type)
	if t != types.String {
		return nil, 0, errors.New("Called [] with wrong type " + t.Label())
	}
	// ^^ TODO

	key := string(args[0].Value)

	m, ok := bind.Value.(map[string]interface{})
	if !ok {
		return nil, 0, errors.New("failed to typecast " + bind.Type.Label() + " into map")
	}
	childType := bind.Type.Child()
	return &RawData{
		Type:  childType,
		Value: m[key],
	}, 0, nil
}

func mapLength(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	if bind.Value == nil {
		return &RawData{Type: types.Int}, 0, nil
	}

	arr, ok := bind.Value.(map[string]interface{})
	if !ok {
		return nil, 0, errors.New("failed to typecast " + bind.Type.Label() + " into map")
	}
	return IntData(int64(len(arr))), 0, nil
}

func mapBlockCall(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return c.runBlock(bind, chunk.Function.Args[0], ref)
}

func dictGetIndex(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	if bind.Value == nil {
		return &RawData{Type: bind.Type}, 0, nil
	}

	switch x := bind.Value.(type) {
	case []interface{}:
		args := chunk.Function.Args

		// TODO: all this needs to go into the compile phase
		if len(args) < 1 {
			return nil, 0, errors.New("Called [] with " + strconv.Itoa(len(args)) + " arguments, only 1 supported.")
		}
		if len(args) > 1 {
			return nil, 0, errors.New("Called [] with " + strconv.Itoa(len(args)) + " arguments, only 1 supported.")
		}
		t := types.Type(args[0].Type)
		if t != types.Int {
			return nil, 0, errors.New("Called [] with wrong type " + t.Label())
		}
		// ^^ TODO

		key := int(bytes2int(args[0].Value))
		return &RawData{
			Value: x[key],
			Type:  bind.Type,
		}, 0, nil

	case map[string]interface{}:
		args := chunk.Function.Args

		// TODO: all this needs to go into the compile phase
		if len(args) < 1 {
			return nil, 0, errors.New("Called [] with " + strconv.Itoa(len(args)) + " arguments, only 1 supported.")
		}
		if len(args) > 1 {
			return nil, 0, errors.New("Called [] with " + strconv.Itoa(len(args)) + " arguments, only 1 supported.")
		}
		t := types.Type(args[0].Type)
		if t != types.String {
			return nil, 0, errors.New("Called [] with wrong type " + t.Label())
		}
		// ^^ TODO

		key := string(args[0].Value)
		return &RawData{
			Value: x[key],
			Type:  bind.Type,
		}, 0, nil
	default:
		return nil, 0, errors.New("dict value does not support accessor `[]`")
	}
}

func dictLength(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	if bind.Value == nil {
		return &RawData{Type: bind.Type}, 0, nil
	}

	switch x := bind.Value.(type) {
	case string:
		return IntData(int64(len(x))), 0, nil
	case []interface{}:
		return IntData(int64(len(x))), 0, nil
	case map[string]interface{}:
		return IntData(int64(len(x))), 0, nil
	default:
		return nil, 0, errors.New("dict value does not support field `length`")
	}
}

func dictBlockCall(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	switch bind.Value.(type) {
	case []interface{}:
		return arrayBlockList(c, bind, chunk, ref)
	default:
		return c.runBlock(bind, chunk.Function.Args[0], ref)
	}
}

func dictDowncase(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	_, ok := bind.Value.(string)
	if !ok {
		return nil, 0, errors.New("dict value does not support field `downcase`")
	}

	return stringDowncase(c, bind, chunk, ref)
}

func dictLines(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	_, ok := bind.Value.(string)
	if !ok {
		return nil, 0, errors.New("dict value does not support field `lines`")
	}

	return stringLines(c, bind, chunk, ref)
}

func dictSplit(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	_, ok := bind.Value.(string)
	if !ok {
		return nil, 0, errors.New("dict value does not support field `split`")
	}

	return stringSplit(c, bind, chunk, ref)
}

func anyContainsString(an interface{}, s string) bool {
	if an == nil {
		return false
	}

	switch x := an.(type) {
	case string:
		return strings.Contains(x, s)
	case []interface{}:
		for i := range x {
			if anyContainsString(x[i], s) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func dictContainsString(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	argRef := chunk.Function.Args[0]
	arg, rref, err := c.resolveValue(argRef, ref)
	if err != nil || rref > 0 {
		return nil, rref, err
	}

	if arg.Value == nil {
		return BoolFalse, 0, nil
	}

	ok := anyContainsString(bind.Value, arg.Value.(string))
	return BoolData(ok), 0, nil
}

func dictContainsArrayString(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	switch bind.Value.(type) {
	case string:
		return stringContainsArrayString(c, bind, chunk, ref)
	default:
		return nil, 0, errors.New("dict value does not support field `contains`")
	}
}

// dict ==/!= nil

func opDictCmpNil(left interface{}, right interface{}) bool {
	return left == nil
}

func opNilCmpDict(left interface{}, right interface{}) bool {
	return right == nil
}

func dictCmpNil(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolOp(c, bind, chunk, ref, opDictCmpNil)
}

func dictNotNil(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolNotOp(c, bind, chunk, ref, opDictCmpNil)
}

func nilCmpDict(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolOp(c, bind, chunk, ref, opNilCmpDict)
}

func nilNotDict(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolNotOp(c, bind, chunk, ref, opNilCmpDict)
}

// dict ==/!= bool

func opDictCmpBool(left interface{}, right interface{}) bool {
	switch x := left.(type) {
	case bool:
		return x == right.(bool)
	case string:
		return opStringCmpBool(x, right)
	default:
		return false
	}
}

func opBoolCmpDict(left interface{}, right interface{}) bool {
	switch x := right.(type) {
	case bool:
		return left.(bool) == x
	case string:
		return opBoolCmpString(left, x)
	default:
		return false
	}
}

func dictCmpBool(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolOp(c, bind, chunk, ref, opDictCmpBool)
}

func dictNotBool(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolNotOp(c, bind, chunk, ref, opDictCmpBool)
}

func boolCmpDict(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolOp(c, bind, chunk, ref, opBoolCmpDict)
}

func boolNotDict(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolNotOp(c, bind, chunk, ref, opBoolCmpDict)
}

// dict ==/!= int   (embedded: string + float)

func opDictCmpInt(left interface{}, right interface{}) bool {
	switch x := left.(type) {
	case int64:
		return x == right.(int64)
	case float64:
		return x == float64(right.(int64))
	case string:
		return opStringCmpInt(x, right)
	default:
		return false
	}
}

func opIntCmpDict(left interface{}, right interface{}) bool {
	switch x := right.(type) {
	case int64:
		return left.(int64) == x
	case float64:
		return float64(left.(int64)) == x
	case string:
		return opIntCmpString(left, x)
	default:
		return false
	}
}

func dictCmpInt(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolOp(c, bind, chunk, ref, opDictCmpInt)
}

func dictNotInt(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolNotOp(c, bind, chunk, ref, opDictCmpInt)
}

func intCmpDict(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolOp(c, bind, chunk, ref, opIntCmpDict)
}

func intNotDict(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolNotOp(c, bind, chunk, ref, opIntCmpDict)
}

// dict ==/!= float

func opDictCmpFloat(left interface{}, right interface{}) bool {
	switch x := left.(type) {
	case int64:
		return float64(x) == right.(float64)
	case float64:
		return x == right.(float64)
	case string:
		return opStringCmpFloat(x, right)
	default:
		return false
	}
}

func opFloatCmpDict(left interface{}, right interface{}) bool {
	switch x := right.(type) {
	case int64:
		return left.(float64) == float64(x)
	case float64:
		return left.(float64) == x
	case string:
		return opFloatCmpString(left, x)
	default:
		return false
	}
}

func dictCmpFloat(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolOp(c, bind, chunk, ref, opDictCmpFloat)
}

func dictNotFloat(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolNotOp(c, bind, chunk, ref, opDictCmpFloat)
}

func floatCmpDict(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolOp(c, bind, chunk, ref, opFloatCmpDict)
}

func floatNotDict(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolNotOp(c, bind, chunk, ref, opFloatCmpDict)
}

// dict ==/!= string

func opDictCmpString(left interface{}, right interface{}) bool {
	switch x := left.(type) {
	case string:
		return x == right.(string)
	case bool:
		return opBoolCmpString(x, right)
	case int64:
		return opIntCmpString(x, right)
	case float64:
		return opFloatCmpString(x, right)
	default:
		return false
	}
}

func opStringCmpDict(left interface{}, right interface{}) bool {
	switch x := right.(type) {
	case string:
		return left.(string) == x
	case bool:
		return opStringCmpBool(left, x)
	case int64:
		return opStringCmpInt(left, x)
	case float64:
		return opStringCmpFloat(left, x)
	default:
		return false
	}
}

func dictCmpString(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolOp(c, bind, chunk, ref, opDictCmpString)
}

func dictNotString(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolNotOp(c, bind, chunk, ref, opDictCmpString)
}

func stringCmpDict(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolOp(c, bind, chunk, ref, opStringCmpDict)
}

func stringNotDict(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolNotOp(c, bind, chunk, ref, opStringCmpDict)
}

// dict ==/!= regex

func opDictCmpRegex(left interface{}, right interface{}) bool {
	switch x := left.(type) {
	case string:
		return opStringCmpRegex(x, right)
	case bool:
		return opBoolCmpRegex(x, right)
	case int64:
		return opIntCmpRegex(x, right)
	case float64:
		return opFloatCmpRegex(x, right)
	default:
		return false
	}
}

func opRegexCmpDict(left interface{}, right interface{}) bool {
	switch x := right.(type) {
	case string:
		return opRegexCmpString(left, x)
	case bool:
		return opRegexCmpBool(left, x)
	case int64:
		return opRegexCmpInt(left, x)
	case float64:
		return opRegexCmpFloat(left, x)
	default:
		return false
	}
}

func dictCmpRegex(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolOp(c, bind, chunk, ref, opDictCmpRegex)
}

func dictNotRegex(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolNotOp(c, bind, chunk, ref, opDictCmpRegex)
}

func regexCmpDict(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolOp(c, bind, chunk, ref, opRegexCmpDict)
}

func regexNotDict(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolNotOp(c, bind, chunk, ref, opRegexCmpDict)
}

// dict ==/!= dict

func opDictCmpDict(left interface{}, right interface{}) bool {
	switch x := left.(type) {
	case bool:
		return opBoolCmpDict(x, right)
	case int64:
		return opIntCmpDict(x, right)
	case float64:
		return opFloatCmpDict(x, right)
	case string:
		return opStringCmpDict(x, right)
	default:
		return false
	}
}

func dictCmpDict(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolOp(c, bind, chunk, ref, opDictCmpDict)
}

func dictNotDict(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolNotOp(c, bind, chunk, ref, opDictCmpDict)
}

// dict </>/<=/>= int

func opDictLTInt(left interface{}, right interface{}) bool {
	switch x := left.(type) {
	case int64:
		return x < right.(int64)
	case float64:
		return x < float64(right.(int64))
	case string:
		f, err := strconv.ParseInt(x, 10, 64)
		return err == nil && f < right.(int64)
	default:
		return false
	}
}

func opDictLTEInt(left interface{}, right interface{}) bool {
	switch x := left.(type) {
	case int64:
		return x <= right.(int64)
	case float64:
		return x <= float64(right.(int64))
	case string:
		f, err := strconv.ParseInt(x, 10, 64)
		return err == nil && f <= right.(int64)
	default:
		return false
	}
}

func dictLTInt(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolOp(c, bind, chunk, ref, opDictLTInt)
}

func dictLTEInt(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolOp(c, bind, chunk, ref, opDictLTEInt)
}

func dictGTInt(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolNotOp(c, bind, chunk, ref, opDictLTEInt)
}

func dictGTEInt(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolNotOp(c, bind, chunk, ref, opDictLTInt)
}

func opIntLTDict(left interface{}, right interface{}) bool {
	switch x := right.(type) {
	case int64:
		return left.(int64) < x
	case float64:
		return float64(left.(int64)) < x
	case string:
		f, err := strconv.ParseInt(x, 10, 64)
		return err == nil && left.(int64) < f
	default:
		return false
	}
}

func opIntLTEDict(left interface{}, right interface{}) bool {
	switch x := right.(type) {
	case int64:
		return left.(int64) <= x
	case float64:
		return float64(left.(int64)) <= x
	case string:
		f, err := strconv.ParseInt(x, 10, 64)
		return err == nil && left.(int64) <= f
	default:
		return false
	}
}

func intLTDict(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolOp(c, bind, chunk, ref, opIntLTDict)
}

func intLTEDict(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolOp(c, bind, chunk, ref, opIntLTEDict)
}

func intGTDict(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolNotOp(c, bind, chunk, ref, opIntLTEDict)
}

func intGTEDict(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolNotOp(c, bind, chunk, ref, opIntLTDict)
}

// dict </>/<=/>= float

func opDictLTFloat(left interface{}, right interface{}) bool {
	switch x := left.(type) {
	case int64:
		return float64(x) < right.(float64)
	case float64:
		return x < right.(float64)
	case string:
		f, err := strconv.ParseFloat(x, 64)
		return err == nil && f < right.(float64)
	default:
		return false
	}
}

func opDictLTEFloat(left interface{}, right interface{}) bool {
	switch x := left.(type) {
	case int64:
		return float64(x) <= right.(float64)
	case float64:
		return x <= right.(float64)
	case string:
		f, err := strconv.ParseFloat(x, 64)
		return err == nil && f <= right.(float64)
	default:
		return false
	}
}

func dictLTFloat(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolOp(c, bind, chunk, ref, opDictLTFloat)
}

func dictLTEFloat(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolOp(c, bind, chunk, ref, opDictLTEFloat)
}

func dictGTFloat(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolNotOp(c, bind, chunk, ref, opDictLTEFloat)
}

func dictGTEFloat(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolNotOp(c, bind, chunk, ref, opDictLTFloat)
}

func opFloatLTDict(left interface{}, right interface{}) bool {
	switch x := right.(type) {
	case int64:
		return left.(float64) < float64(x)
	case float64:
		return left.(float64) < x
	case string:
		f, err := strconv.ParseFloat(x, 64)
		return err == nil && left.(float64) < f
	default:
		return false
	}
}

func opFloatLTEDict(left interface{}, right interface{}) bool {
	switch x := right.(type) {
	case int64:
		return left.(float64) <= float64(x)
	case float64:
		return left.(float64) <= x
	case string:
		f, err := strconv.ParseFloat(x, 64)
		return err == nil && left.(float64) <= f
	default:
		return false
	}
}

func floatLTDict(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolOp(c, bind, chunk, ref, opFloatLTDict)
}

func floatLTEDict(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolOp(c, bind, chunk, ref, opFloatLTEDict)
}

func floatGTDict(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolNotOp(c, bind, chunk, ref, opFloatLTEDict)
}

func floatGTEDict(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolNotOp(c, bind, chunk, ref, opFloatLTDict)
}

// dict </>/<=/>= string

func opDictLTString(left interface{}, right interface{}) bool {
	switch x := left.(type) {
	case int64:
		f, err := strconv.ParseInt(right.(string), 10, 64)
		return err == nil && x < f
	case float64:
		f, err := strconv.ParseFloat(right.(string), 64)
		return err == nil && x < f
	case string:
		return x < right.(string)
	default:
		return false
	}
}

func opDictLTEString(left interface{}, right interface{}) bool {
	switch x := left.(type) {
	case int64:
		f, err := strconv.ParseInt(right.(string), 10, 64)
		return err == nil && x <= f
	case float64:
		f, err := strconv.ParseFloat(right.(string), 64)
		return err == nil && x <= f
	case string:
		return x <= right.(string)
	default:
		return false
	}
}

func dictLTString(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolOp(c, bind, chunk, ref, opDictLTString)
}

func dictLTEString(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolOp(c, bind, chunk, ref, opDictLTEString)
}

func dictGTString(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolNotOp(c, bind, chunk, ref, opDictLTEString)
}

func dictGTEString(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolNotOp(c, bind, chunk, ref, opDictLTString)
}

func opStringLTDict(left interface{}, right interface{}) bool {
	switch x := right.(type) {
	case int64:
		f, err := strconv.ParseInt(left.(string), 10, 64)
		return err == nil && f < x
	case float64:
		f, err := strconv.ParseFloat(left.(string), 64)
		return err == nil && f < x
	case string:
		return left.(string) < x
	default:
		return false
	}
}

func opStringLTEDict(left interface{}, right interface{}) bool {
	switch x := right.(type) {
	case int64:
		f, err := strconv.ParseInt(left.(string), 10, 64)
		return err == nil && f <= x
	case float64:
		f, err := strconv.ParseFloat(left.(string), 64)
		return err == nil && f <= x
	case string:
		return left.(string) <= x
	default:
		return false
	}
}

func stringLTDict(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolOp(c, bind, chunk, ref, opStringLTDict)
}

func stringLTEDict(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolOp(c, bind, chunk, ref, opStringLTEDict)
}

func stringGTDict(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolNotOp(c, bind, chunk, ref, opStringLTEDict)
}

func stringGTEDict(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolNotOp(c, bind, chunk, ref, opStringLTDict)
}

// dict </>/<=/>= dict

func dictLTDict(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolOp(c, bind, chunk, ref, func(left interface{}, right interface{}) bool {
		switch x := right.(type) {
		case int64:
			return opDictLTInt(left, x)
		case float64:
			return opDictLTFloat(left, x)
		case string:
			return opDictLTString(left, x)
		default:
			return false
		}
	})
}

func dictLTEDict(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolOp(c, bind, chunk, ref, func(left interface{}, right interface{}) bool {
		switch x := right.(type) {
		case int64:
			return opDictLTEInt(left, x)
		case float64:
			return opDictLTEFloat(left, x)
		case string:
			return opDictLTEString(left, x)
		default:
			return false
		}
	})
}

func dictGTDict(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolNotOp(c, bind, chunk, ref, func(left interface{}, right interface{}) bool {
		switch x := right.(type) {
		case int64:
			return opDictLTEInt(left, x)
		case float64:
			return opDictLTEFloat(left, x)
		case string:
			return opDictLTString(left, x)
		default:
			return false
		}
	})
}

func dictGTEDict(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolNotOp(c, bind, chunk, ref, func(left interface{}, right interface{}) bool {
		switch x := right.(type) {
		case int64:
			return opDictLTInt(left, x)
		case float64:
			return opDictLTFloat(left, x)
		case string:
			return opDictLTString(left, x)
		default:
			return false
		}
	})
}

// dict && / || ...

func truthyDict(value interface{}) bool {
	switch x := value.(type) {
	case bool:
		return x
	case int64:
		return x != 0
	case float64:
		return x != 0
	case string:
		return x != ""
	case []interface{}:
		return len(x) != 0
	case map[string]interface{}:
		return len(x) != 0
	default:
		return false
	}
}

// ... bool

func opBoolAndDict(left interface{}, right interface{}) bool {
	return left.(bool) && truthyDict(right)
}

func opBoolOrDict(left interface{}, right interface{}) bool {
	return left.(bool) || truthyDict(right)
}

func opDictAndBool(left interface{}, right interface{}) bool {
	return truthyDict(left) && right.(bool)
}

func opDictOrBool(left interface{}, right interface{}) bool {
	return truthyDict(left) || right.(bool)
}

func boolAndDict(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolOp(c, bind, chunk, ref, opBoolAndDict)
}

func boolOrDict(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolOp(c, bind, chunk, ref, opBoolOrDict)
}

func dictAndBool(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolOp(c, bind, chunk, ref, opDictAndBool)
}

func dictOrBool(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolOp(c, bind, chunk, ref, opDictOrBool)
}

// ... int

func opIntAndDict(left interface{}, right interface{}) bool {
	return left.(int64) != 0 && truthyDict(right)
}

func opIntOrDict(left interface{}, right interface{}) bool {
	return left.(int64) != 0 || truthyDict(right)
}

func opDictAndInt(left interface{}, right interface{}) bool {
	return truthyDict(left) && right.(int64) != 0
}

func opDictOrInt(left interface{}, right interface{}) bool {
	return truthyDict(left) || right.(int64) != 0
}

func intAndDict(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolOp(c, bind, chunk, ref, opIntAndDict)
}

func intOrDict(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolOp(c, bind, chunk, ref, opIntOrDict)
}

func dictAndInt(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolOp(c, bind, chunk, ref, opDictAndInt)
}

func dictOrInt(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolOp(c, bind, chunk, ref, opDictOrInt)
}

// ... float

func opFloatAndDict(left interface{}, right interface{}) bool {
	return left.(float64) != 0 && truthyDict(right)
}

func opFloatOrDict(left interface{}, right interface{}) bool {
	return left.(float64) != 0 || truthyDict(right)
}

func opDictAndFloat(left interface{}, right interface{}) bool {
	return truthyDict(left) && right.(float64) != 0
}

func opDictOrFloat(left interface{}, right interface{}) bool {
	return truthyDict(left) || right.(float64) != 0
}

func floatAndDict(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolOp(c, bind, chunk, ref, opFloatAndDict)
}

func floatOrDict(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolOp(c, bind, chunk, ref, opFloatOrDict)
}

func dictAndFloat(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolOp(c, bind, chunk, ref, opDictAndFloat)
}

func dictOrFloat(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolOp(c, bind, chunk, ref, opDictOrFloat)
}

// ... string

func opStringAndDict(left interface{}, right interface{}) bool {
	return left.(string) != "" && truthyDict(right)
}

func opStringOrDict(left interface{}, right interface{}) bool {
	return left.(string) != "" || truthyDict(right)
}

func opDictAndString(left interface{}, right interface{}) bool {
	return truthyDict(left) && right.(string) != ""
}

func opDictOrString(left interface{}, right interface{}) bool {
	return truthyDict(left) || right.(string) != ""
}

func stringAndDict(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolOp(c, bind, chunk, ref, opStringAndDict)
}

func stringOrDict(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolOp(c, bind, chunk, ref, opStringOrDict)
}

func dictAndString(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolOp(c, bind, chunk, ref, opDictAndString)
}

func dictOrString(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolOp(c, bind, chunk, ref, opDictOrString)
}

// ... regex

func opRegexAndDict(left interface{}, right interface{}) bool {
	return left.(string) != "" && truthyDict(right)
}

func opRegexOrDict(left interface{}, right interface{}) bool {
	return left.(string) != "" || truthyDict(right)
}

func opDictAndRegex(left interface{}, right interface{}) bool {
	return truthyDict(left) && right.(string) != ""
}

func opDictOrRegex(left interface{}, right interface{}) bool {
	return truthyDict(left) || right.(string) != ""
}

func regexAndDict(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolOp(c, bind, chunk, ref, opRegexAndDict)
}

func regexOrDict(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolOp(c, bind, chunk, ref, opRegexOrDict)
}

func dictAndRegex(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolOp(c, bind, chunk, ref, opDictAndRegex)
}

func dictOrRegex(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolOp(c, bind, chunk, ref, opDictOrRegex)
}

// ... time
// note: time cannot be falsy

func opTimeAndDict(left interface{}, right interface{}) bool {
	return truthyDict(right)
}

func opTimeOrDict(left interface{}, right interface{}) bool {
	return true
}

func opDictAndTime(left interface{}, right interface{}) bool {
	return truthyDict(left)
}

func opDictOrTime(left interface{}, right interface{}) bool {
	return true
}

func timeAndDict(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolOp(c, bind, chunk, ref, opTimeAndDict)
}

func timeOrDict(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolOp(c, bind, chunk, ref, opTimeOrDict)
}

func dictAndTime(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolOp(c, bind, chunk, ref, opDictAndTime)
}

func dictOrTime(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolOp(c, bind, chunk, ref, opDictOrTime)
}

// ... dict

func opDictAndDict(left interface{}, right interface{}) bool {
	return truthyDict(left) && truthyDict(right)
}

func opDictOrDict(left interface{}, right interface{}) bool {
	return truthyDict(left) || truthyDict(right)
}

func dictAndDict(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolOp(c, bind, chunk, ref, opDictAndDict)
}

func dictOrDict(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolOp(c, bind, chunk, ref, opDictOrDict)
}

// ... array

func opDictAndArray(left interface{}, right interface{}) bool {
	return truthyDict(left) && (len(right.([]interface{})) != 0)
}

func opArrayAndDict(left interface{}, right interface{}) bool {
	return truthyDict(right) && (len(left.([]interface{})) != 0)
}

func opDictOrArray(left interface{}, right interface{}) bool {
	return truthyDict(left) || (len(right.([]interface{})) != 0)
}

func opArrayOrDict(left interface{}, right interface{}) bool {
	return truthyDict(right) || (len(left.([]interface{})) != 0)
}

func dictAndArray(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolOp(c, bind, chunk, ref, opDictAndArray)
}

func dictOrArray(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolOp(c, bind, chunk, ref, opDictOrArray)
}

func arrayAndDict(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolOp(c, bind, chunk, ref, opArrayAndDict)
}

func arrayOrDict(c *LeiseExecutor, bind *RawData, chunk *Chunk, ref int32) (*RawData, int32, error) {
	return boolOp(c, bind, chunk, ref, opArrayOrDict)
}
