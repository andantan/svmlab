package misc

import (
	"errors"
	"fmt"
	"strings"
)

// RawRequest passes a method straight through to the node.
//
// It exists so that a method this API has not wrapped is still reachable,
// which is most of the point of a lab.
type RawRequest struct {
	Method string `json:"method" example:"getEpochInfo"`
	Params any    `json:"params"`
}

func (r *RawRequest) ValidateRequest() error {
	r.Method = strings.TrimSpace(r.Method)
	if r.Method == "" {
		return errors.New("method is required")
	}

	return nil
}

type BatchCall struct {
	Method string `json:"method"`
	Params any    `json:"params"`
}

// BatchRequest sends several calls in one round trip.
type BatchRequest struct {
	Calls []BatchCall `json:"calls"`
}

func (r *BatchRequest) ValidateRequest() error {
	if len(r.Calls) == 0 {
		return errors.New("calls: at least one is required")
	}
	for i := range r.Calls {
		r.Calls[i].Method = strings.TrimSpace(r.Calls[i].Method)
		if r.Calls[i].Method == "" {
			return fmt.Errorf("calls[%d].method is required", i)
		}
	}

	return nil
}
