// Package nilguard holds the one reflection-based nil check every
// build-time guard in this module needs, so each guard states only what
// is specific to it — which interface, which error or panic message, when
// the check runs — while the mechanics of "how do I even tell a nil from
// a nil" live in exactly one place instead of four or five near-identical
// copies, one per call site.
package nilguard

import "reflect"

// IsNilValue reports whether v is nil in every sense that matters for an
// interface-typed constructor parameter: the bare nil literal, or a
// non-nil interface value whose *concrete* value is nil — a nil pointer,
// map, slice, channel or func wrapped in the interface.
//
// A caller who declares a concrete variable and forgets to initialise it —
// `var v *myImpl; WithX(v)` — hands the receiving option an interface
// value that is != nil (it carries a concrete type, *myImpl) even though
// calling any method on it would dereference that nil pointer. A plain
// `v == nil` alone does not catch this; only reflection does, which is
// exactly what this function exists to centralise.
//
// v is intended to be an interface-typed value whose interface declares
// at least one method — access.Decider, io.Writer, origin.List and
// identity.Verifier all qualify, and are exactly what every call site in
// this module passes in. Two of reflect's Kinds are deliberately absent
// from the switch below for any such value, not by oversight:
//
//   - reflect.Interface: an interface value can never itself hold another
//     interface as its dynamic type — assigning any value to an
//     interface-typed variable always stores that value's already-concrete
//     dynamic type, so reflect.ValueOf(v).Kind() can never report
//     Interface here, however many interface-typed variables the value
//     passed through on its way in.
//   - reflect.UnsafePointer: only ever reported for a value of a defined
//     type whose underlying type is unsafe.Pointer itself, and Go's
//     method-declaration rules refuse a receiver of that shape outright
//     (`invalid receiver type T (unsafe.Pointer)`, a compiler error). No
//     such type can implement a method — any method — in the first
//     place, so no value of it can ever satisfy an interface that
//     declares one, and therefore never reach here as v.
func IsNilValue(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Chan, reflect.Func:
		return rv.IsNil()
	default:
		// A struct value, an int, anything else that cannot be nil in
		// the first place: nothing more to check.
		return false
	}
}
