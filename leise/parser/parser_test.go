package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.io/mondoo/logger"
)

func init() {
	logger.InitTestEnv()
}

func TestParser_Lex(t *testing.T) {
	tests := []struct {
		typ rune
		str string
	}{
		{Ident, "name"},
		{Float, "1.23"},
		{Int, "123"},
		{String, "'hi'"},
		{String, "\"hi\""},
		{Regex, "/regex/"},
		{Op, "+"},
	}
	for i := range tests {
		res, err := Lex(tests[i].str)
		assert.Nil(t, err)
		assert.Equal(t, tests[i].typ, res[0].Type)
	}
}

func vBool(b bool) *Value {
	return &Value{Bool: &b}
}

func vIdent(v string) *Value {
	return &Value{Ident: &v}
}

func vFloat(v float64) *Value {
	return &Value{Float: &v}
}

func vInt(v int64) *Value {
	return &Value{Int: &v}
}

func vString(v string) *Value {
	return &Value{String: &v}
}

func vRegex(v string) *Value {
	return &Value{Regex: &v}
}

func callIdent(ident string) *Call {
	return &Call{Ident: &ident}
}
func TestParser_ParseValues(t *testing.T) {
	tests := []struct {
		code string
		res  *Expression
	}{
		{"true", &Expression{Operand: &Operand{Value: vBool(true)}}},
		{"false", &Expression{Operand: &Operand{Value: vBool(false)}}},
		{"name", &Expression{Operand: &Operand{Value: vIdent("name")}}},
		{"1.23", &Expression{Operand: &Operand{Value: vFloat(1.23)}}},
		{"123", &Expression{Operand: &Operand{Value: vInt(123)}}},
		{"'hi'", &Expression{Operand: &Operand{Value: vString("hi")}}},
		{"\"hi\"", &Expression{Operand: &Operand{Value: vString("hi")}}},
		{"/hi/", &Expression{Operand: &Operand{Value: vRegex("hi")}}},
		{"[]", &Expression{Operand: &Operand{Value: &Value{Array: []*Expression{}}}}},
		{"[1]", &Expression{Operand: &Operand{Value: &Value{Array: []*Expression{
			{Operand: &Operand{Value: vInt(1)}},
		}}}}},
		{"[1,2.3]", &Expression{Operand: &Operand{Value: &Value{Array: []*Expression{
			{Operand: &Operand{Value: vInt(1)}},
			{Operand: &Operand{Value: vFloat(2.3)}},
		}}}}},
		{"name.last", &Expression{Operand: &Operand{
			Value: vIdent("name"),
			Calls: []*Call{callIdent("last")},
		}}},
		{"name[1]", &Expression{Operand: &Operand{
			Value: vIdent("name"),
			Calls: []*Call{{Accessor: &Expression{Operand: &Operand{Value: vInt(1)}}}},
		}}},
		{"name()", &Expression{Operand: &Operand{
			Value: vIdent("name"),
			Calls: []*Call{{Function: []*Arg{}}},
		}}},
		{"name(1)", &Expression{Operand: &Operand{
			Value: vIdent("name"),
			Calls: []*Call{{Function: []*Arg{
				{Value: &Expression{Operand: &Operand{Value: vInt(1)}}},
			}}},
		}}},
		{"name(arg)", &Expression{Operand: &Operand{
			Value: vIdent("name"),
			Calls: []*Call{{Function: []*Arg{
				{Value: &Expression{Operand: &Operand{Value: vIdent("arg")}}},
			}}},
		}}},
		{"name(uid: 1)", &Expression{Operand: &Operand{
			Value: vIdent("name"),
			Calls: []*Call{{Function: []*Arg{
				{Name: "uid", Value: &Expression{Operand: &Operand{Value: vInt(1)}}},
			}}},
		}}},
		{"a(b(c,d))", &Expression{Operand: &Operand{
			Value: vIdent("a"),
			Calls: []*Call{{Function: []*Arg{
				{Value: &Expression{Operand: &Operand{
					Value: vIdent("b"),
					Calls: []*Call{{Function: []*Arg{
						{Value: &Expression{Operand: &Operand{Value: vIdent("c")}}},
						{Value: &Expression{Operand: &Operand{Value: vIdent("d")}}},
					}}},
				}}},
			}}},
		}}},
		{"user { name uid }", &Expression{Operand: &Operand{
			Value: vIdent("user"),
			Block: []*Expression{
				{Operand: &Operand{Value: vIdent("name")}},
				{Operand: &Operand{Value: vIdent("uid")}},
			},
		}}},
		{"users.list { uid }", &Expression{Operand: &Operand{
			Value: vIdent("users"),
			Calls: []*Call{callIdent("list")},
			Block: []*Expression{
				{Operand: &Operand{Value: vIdent("uid")}},
			},
		}}},
		{"users.where(uid > 2).list { uid }", &Expression{Operand: &Operand{
			Value: vIdent("users"),
			Calls: []*Call{
				callIdent("where"),
				{Function: []*Arg{{Value: &Expression{
					Operand: &Operand{Value: vIdent("uid")},
					Operations: []*Operation{{
						Operator: OpGreater,
						Operand:  &Operand{Value: vInt(2)},
					}},
				}}}},
				callIdent("list"),
			},
			Block: []*Expression{
				{Operand: &Operand{Value: vIdent("uid")}},
			},
		}}},
		{"1 + 2 == 3", &Expression{
			Operand: &Operand{Value: vInt(1)},
			Operations: []*Operation{
				{Operator: OpAdd, Operand: &Operand{Value: vInt(2)}},
				{Operator: OpEqual, Operand: &Operand{Value: vInt(3)}},
			},
		}},
		{"true + 'some'.length()", &Expression{
			Operand: &Operand{Value: vBool(true)},
			Operations: []*Operation{
				{Operator: OpAdd, Operand: &Operand{
					Value: vString("some"),
					Calls: []*Call{callIdent("length"), {Function: []*Arg{}}},
				}},
			},
		}},
	}
	for i := range tests {
		test := tests[i]

		t.Run(test.code, func(t *testing.T) {
			res, err := Parse(test.code)
			if err != nil {
				assert.Nil(t, err)
				return
			}
			if res == nil || res.Expressions == nil {
				assert.Equal(t, 1, len(res.Expressions), "parsing must generate one expression")
				return
			}

			assert.Equal(t, test.res, res.Expressions[0])
		})
	}
}
