package hostnetwork

import (
	"encoding/json"

	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/jsonstrict"
)

// Only restored historical desktop records survive decoding. Their original
// data is retained privately and cannot be constructed by a Core mutation plan.
// Unfinished legacy debt is never guessed, discarded or sent to an OS backend.
func (s *Step) UnmarshalJSON(b []byte) error {
	var wire struct {
		Key               json.RawMessage   `json:"key"`
		Before            json.RawMessage   `json:"before,omitempty"`
		After             json.RawMessage   `json:"after,omitempty"`
		State             string            `json:"state"`
		Intermediates     []json.RawMessage `json:"intermediates,omitempty"`
		BeforeFingerprint string            `json:"before_fingerprint,omitempty"`
	}
	if err := jsonstrict.DecodeLimit(b, &wire, MaxJournalBytes); err != nil {
		return err
	}
	var key struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(wire.Key, &key); err != nil {
		return err
	}
	if key.Kind == "proxy" || key.Kind == "wininet" {
		if wire.State != "restored" {
			return identity.Err(identity.NotImplemented, "unfinished deprecated desktop recovery debt; original journal retained")
		}
		if len(wire.Intermediates) > 64 || len(wire.BeforeFingerprint) > 64 {
			return identity.Err(identity.Corrupt, "invalid historical recovery record")
		}
		for _, raw := range append([]json.RawMessage{wire.Before, wire.After}, wire.Intermediates...) {
			if len(raw) == 0 || string(raw) == "null" {
				continue
			}
			var record struct {
				Kind string `json:"kind"`
			}
			if json.Unmarshal(raw, &record) != nil || record.Kind != key.Kind {
				return identity.Err(identity.Corrupt, "inconsistent historical recovery record")
			}
		}
		*s = Step{Key: Record{Kind: key.Kind}, State: "restored", legacy: append(json.RawMessage(nil), b...)}
		return nil
	}
	type coreStep Step
	var core coreStep
	if err := jsonstrict.DecodeLimit(b, &core, MaxJournalBytes); err != nil {
		return err
	}
	*s = Step(core)
	return nil
}

func (s Step) MarshalJSON() ([]byte, error) {
	if s.legacy != nil {
		if s.State != "restored" {
			return nil, identity.Err(identity.Corrupt, "historical recovery state changed")
		}
		return append([]byte(nil), s.legacy...), nil
	}
	type coreStep Step
	return json.Marshal(coreStep(s))
}
