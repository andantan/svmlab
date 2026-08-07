package rpc

// Elem is one JSON-RPC call: the method, its params, and a pointer the result
// is decoded into.
//
// Keeping the result as a pointer rather than a return value is what lets a
// batch decode heterogeneous results in one round trip.
type Elem struct {
	Method string
	Params any
	Result any
}

type Elems []Elem

func (e *Elems) With(elem Elem) *Elems {
	*e = append(*e, elem)

	return e
}

func (e *Elems) Len() int {
	return len(*e)
}

func (e *Elems) GetMethod(i int) string {
	return (*e)[i].Method
}

func (e *Elems) GetParams(i int) any {
	return (*e)[i].Params
}

func (e *Elems) GetResult(i int) any {
	return (*e)[i].Result
}
