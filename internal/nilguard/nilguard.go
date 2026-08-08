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
// v is *expected* to be an interface-typed value whose interface declares
// at least one method — access.Decider, io.Writer, origin.List and
// identity.Verifier all qualify, and are exactly what every real call
// site in this module passes in. That expectation is documented here,
// not enforced by v's own type: v is `any`, so nothing stops a future
// internal caller from passing something that never went through one of
// those four interfaces at all. The switch below is written to stay
// correct even then, rather than relying on the four real call sites to
// keep it honest by construction:
//
//   - reflect.Pointer, reflect.Map, reflect.Slice, reflect.Chan,
//     reflect.Func, reflect.UnsafePointer: all six are included, covering
//     every Kind reflect.Value.IsNil accepts. A value of one of the first
//     five Kinds reaching here through one of the four documented
//     interfaces is exactly the case this function exists for (see the
//     package doc). reflect.UnsafePointer earns its place differently: no
//     type whose underlying type is unsafe.Pointer can implement a
//     method (Go's method-declaration rules refuse that receiver shape
//     outright, a compile error), so none of the four real interfaces —
//     each declaring at least one method — could ever hand this function
//     a value of that Kind. A bare unsafe.Pointer value has no such
//     restriction, though, and Go happily boxes one directly into `any`
//     with Kind reflect.UnsafePointer — reachable here precisely because
//     v's own type does not rule it out the way a >=1-method interface
//     parameter would. Excluding it would have been correct only under
//     an assumption this function's signature does not actually enforce.
//   - reflect.Interface is the one Kind excluded on a proof that holds
//     regardless of v's static type: an interface value can never itself
//     hold another interface as its dynamic type. Assigning any value —
//     concrete or itself already interface-typed — to an interface-typed
//     variable always stores that value's already-concrete dynamic type,
//     so reflect.ValueOf(v).Kind() can never report Interface, no matter
//     how many interface-typed variables (stubInterface, io.Writer,
//     `any` itself) the value passed through on its way here. This is
//     the only exclusion that survives generalising from a specific
//     >=1-method interface to `any`.
func IsNilValue(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Chan, reflect.Func, reflect.UnsafePointer:
		return rv.IsNil()
	default:
		// A struct value, an int, anything else that cannot be nil in
		// the first place: nothing more to check.
		return false
	}
}
