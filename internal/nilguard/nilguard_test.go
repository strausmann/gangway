package nilguard_test

import (
	"testing"
	"unsafe"

	"github.com/strausmann/gangway/internal/nilguard"
)

// stubInterface is the minimal interface every case below is expressed
// through, standing in for access.Decider, io.Writer, origin.List and
// identity.Verifier — all single-method interfaces IsNilValue is meant to
// guard. What the one method actually does is irrelevant here: IsNilValue
// never calls it, only reflects on the value carrying it.
type stubInterface interface {
	Marker()
}

type validStub struct{}

func (validStub) Marker() {}

type ptrStub struct{}

func (*ptrStub) Marker() {}

type mapStub map[string]int

func (mapStub) Marker() {}

type sliceStub []int

func (sliceStub) Marker() {}

type chanStub chan struct{}

func (chanStub) Marker() {}

type funcStub func()

func (funcStub) Marker() {}

// TestIsNilValue is table-driven across every case that matters: a real,
// usable value (regression guard — IsNilValue must never flag something
// that is actually fine), the bare nil literal, and a typed nil for each
// of the five nilable kinds the doc comment promises are checked
// (Pointer, Map, Slice, Chan, Func). Removing any one case from
// IsNilValue's switch fails precisely the matching subtest here, not a
// coincidental one — the same guarantee
// TestNewRejectsATypedNilVerifierForEveryNilableKind gives isNilVerifier
// in package serve, which this table mirrors.
func TestIsNilValue(t *testing.T) {
	var nilMap mapStub
	var nilSlice sliceStub
	var nilChan chanStub
	var nilFunc funcStub

	cases := []struct {
		name string
		v    stubInterface
		want bool
	}{
		{"valid struct value", validStub{}, false},
		{"bare nil literal", nil, true},
		{"typed nil pointer", (*ptrStub)(nil), true},
		{"typed nil map", nilMap, true},
		{"typed nil slice", nilSlice, true},
		{"typed nil chan", nilChan, true},
		{"typed nil func", nilFunc, true},
		{"non-nil map", mapStub{"a": 1}, false},
		{"non-nil slice", sliceStub{1}, false},
		{"non-nil chan", chanStub(make(chan struct{})), false},
		{"non-nil func", funcStub(func() {}), false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := nilguard.IsNilValue(tc.v)
			if got != tc.want {
				t.Errorf("IsNilValue(%#v) = %v, want %v", tc.v, got, tc.want)
			}
		})
	}
}

// TestIsNilValueOnNonInterfaceValues proves IsNilValue does not misfire
// on values that were never nilable in the first place — an int, a plain
// (non-pointer) struct passed as `any` rather than through the narrower
// stubInterface the table above uses. These are the "default: return
// false" branch's only reachable inputs in practice, and a regression
// that made that branch report true would fail every other check in this
// package's callers (WithDecider, WithLogWriter, accesslog.Middleware,
// origin.Combine all guard interface-typed parameters, never bare ints —
// this test exists so the fallback branch itself has direct coverage,
// not just an inference from the interface-typed cases above).
func TestIsNilValueOnNonInterfaceValues(t *testing.T) {
	cases := []struct {
		name string
		v    any
	}{
		{"int", 42},
		{"struct value", struct{ N int }{N: 1}},
		{"string", "not nilable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if nilguard.IsNilValue(tc.v) {
				t.Errorf("IsNilValue(%#v) = true, want false", tc.v)
			}
		})
	}
}

// TestIsNilValueOnUnsafePointer is the regression guard for the gap the
// review found in the original four-interface-only reasoning: every real
// call site in this module (access.Decider, io.Writer, origin.List,
// identity.Verifier) requires at least one method, and Go's
// method-declaration rules refuse a receiver whose underlying type is
// unsafe.Pointer — so, for those four, a value of Kind
// reflect.UnsafePointer could never reach IsNilValue in the first place.
//
// IsNilValue's own parameter is `any`, though, not one of those four
// specifically — nothing about the function's own signature enforces the
// "came through a >=1-method interface" precondition its doc comment
// states. A future internal caller (this package has no external callers;
// it is unexported at the module boundary) could pass a bare
// unsafe.Pointer directly, unrelated to any of the four guarded
// interfaces, and unlike the four real call sites, that is not a
// compile-time impossibility here — only a documented expectation. This
// test exists so that expectation is also enforced in the type, not only
// asserted in prose: a nil unsafe.Pointer, wrapped directly in `any`
// (never through stubInterface — unsafe.Pointer cannot implement
// Marker(), or any method, at all), must be reported as nil.
func TestIsNilValueOnUnsafePointer(t *testing.T) {
	var nilPtr unsafe.Pointer
	if !nilguard.IsNilValue(nilPtr) {
		t.Error("IsNilValue(nil unsafe.Pointer) = false, want true")
	}

	var x int
	nonNilPtr := unsafe.Pointer(&x)
	if nilguard.IsNilValue(nonNilPtr) {
		t.Error("IsNilValue(non-nil unsafe.Pointer) = true, want false")
	}
}
