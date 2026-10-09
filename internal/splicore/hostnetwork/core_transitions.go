package hostnetwork

func knownTransition(current *Record, s Step) bool {
	if equal(current, s.After) {
		return true
	}
	if s.State == "pending" && current != nil && s.After != nil && s.Key.Kind == "interface" && s.After.Adapter != nil {
		// Creation can crash before applying MTU or acknowledging an index. The
		// backend has verified the durable random GUID; constructor defaults are
		// still owned. Applied interfaces retain exact-state conflict detection.
		candidate := cloneRecord(current)
		candidate.Index = s.After.Index
		candidate.MTU = s.After.MTU
		if equal(candidate, s.After) {
			return true
		}
	}
	if current != nil && s.After != nil && s.After.Adapter != nil && current.Index > 0 && s.After.Index == 0 {
		candidate := cloneRecord(current)
		candidate.Index = 0
		if equal(candidate, s.After) {
			return true
		}
	}
	if current != nil && s.After != nil && s.Key.Kind == "interface" && s.After.Adapter != nil && current.Index == 0 {
		candidate := cloneRecord(current)
		candidate.Index = s.After.Index
		if equal(candidate, s.After) {
			return true
		}
	}
	return false
}
