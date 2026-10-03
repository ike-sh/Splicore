package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/client"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/jsonstrict"
)

func (s *Store) ClientState(ctx context.Context) (client.ProfileState, error) {
	s.write.Lock()
	defer s.write.Unlock()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return client.ProfileState{}, storageError(err)
	}
	defer tx.Rollback()
	state := client.Empty()
	if err = tx.QueryRowContext(ctx, "SELECT committed_revision FROM settings WHERE singleton=1").Scan(&state.Revision); err != nil {
		return state, storageError(err)
	}
	if err = tx.QueryRowContext(ctx, "SELECT enabled FROM client_profiles WHERE singleton=1").Scan(&state.Enabled); err != nil {
		return state, storageError(err)
	}
	if err = tx.QueryRowContext(ctx, "SELECT default_outbound FROM client_routes WHERE singleton=1").Scan(&state.Route.DefaultOutbound); err != nil {
		return state, storageError(err)
	}
	var networkDocument []byte
	if err = tx.QueryRowContext(ctx, "SELECT document FROM client_network_profiles WHERE singleton=1").Scan(&networkDocument); err != nil {
		return state, storageError(err)
	}
	if jsonstrict.DecodeLimit(networkDocument, &state.Network, 2<<20) != nil {
		return state, identity.Err(identity.Corrupt, "invalid committed network configuration")
	}
	state.Outbounds = []client.Outbound{}
	for _, read := range []struct {
		query  string
		decode func([]byte) error
	}{
		{"SELECT document FROM remote_nodes ORDER BY id LIMIT 129", func(b []byte) error {
			var n client.RemoteNode
			if e := json.Unmarshal(b, &n); e != nil {
				return e
			}
			state.Nodes = append(state.Nodes, n)
			return nil
		}},
		{"SELECT document FROM client_outbounds ORDER BY id LIMIT 130", func(b []byte) error {
			var n client.Outbound
			if e := json.Unmarshal(b, &n); e != nil {
				return e
			}
			state.Outbounds = append(state.Outbounds, n)
			return nil
		}},
		{"SELECT document FROM local_inbounds ORDER BY id LIMIT 33", func(b []byte) error {
			var n client.LocalInbound
			if e := json.Unmarshal(b, &n); e != nil {
				return e
			}
			state.LocalInbounds = append(state.LocalInbounds, n)
			return nil
		}},
	} {
		rows, e := tx.QueryContext(ctx, read.query)
		if e != nil {
			return state, storageError(e)
		}
		for rows.Next() {
			var b []byte
			if e = rows.Scan(&b); e == nil {
				e = read.decode(b)
			}
			if e != nil {
				break
			}
		}
		if e == nil {
			e = rows.Err()
		}
		rows.Close()
		if e != nil {
			return client.ProfileState{}, identity.Err(identity.Corrupt, "invalid committed client state")
		}
	}
	if state.Validate() != nil {
		return client.ProfileState{}, identity.Err(identity.Corrupt, "invalid committed client state")
	}
	return state, nil
}

// ReplaceClient runs only inside the existing short commit callback; no network I/O.
func (w *writer) ReplaceClient(state client.ProfileState, secrets []access.Credential) error {
	if err := state.Validate(); err != nil {
		return err
	}
	for _, q := range []string{"DELETE FROM client_routes", "DELETE FROM local_inbounds", "DELETE FROM client_outbounds"} {
		if err := w.exec(q); err != nil {
			return err
		}
	}
	for _, n := range state.Nodes {
		b, _ := json.Marshal(n)
		if err := w.exec("INSERT INTO remote_nodes VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET credential_id=excluded.credential_id,document=excluded.document", n.ID, n.CredentialID, string(b)); err != nil {
			return err
		}
	}
	for _, c := range secrets {
		if c.OwnerNodeID == nil {
			return identity.Err(identity.Invalid, "remote credential owner required")
		}
		if err := w.CreateCredential(c); err != nil {
			return err
		}
	}
	// Drop obsolete remote credentials and nodes. Server credentials never enter this scope.
	keep := map[identity.ID]bool{}
	for _, n := range state.Nodes {
		keep[n.ID] = true
	}
	rows, err := w.tx.QueryContext(w.ctx, "SELECT id FROM remote_nodes")
	if err != nil {
		return storageError(err)
	}
	remove := []identity.ID{}
	for rows.Next() {
		var id identity.ID
		if err = rows.Scan(&id); err != nil {
			break
		}
		if !keep[id] {
			remove = append(remove, id)
		}
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return storageError(err)
	}
	for _, id := range remove {
		if err = w.exec("DELETE FROM credentials WHERE remote_node_id=?", id); err != nil {
			return err
		}
		if err = w.exec("DELETE FROM remote_nodes WHERE id=?", id); err != nil {
			return err
		}
	}
	if err = w.exec("DELETE FROM credentials WHERE remote_node_id IS NOT NULL AND id NOT IN (SELECT credential_id FROM remote_nodes)"); err != nil {
		return err
	}
	for _, o := range state.Outbounds {
		b, _ := json.Marshal(o)
		if err = w.exec("INSERT INTO client_outbounds VALUES(?,?,?)", o.ID, o.NodeID, string(b)); err != nil {
			return err
		}
	}
	for _, i := range state.LocalInbounds {
		b, _ := json.Marshal(i)
		var id any
		if i.SelectedOutbound != "" {
			id = i.SelectedOutbound
		}
		if err = w.exec("INSERT INTO local_inbounds VALUES(?,?,?)", i.ID, id, string(b)); err != nil {
			return err
		}
	}
	if err = w.exec("INSERT INTO client_routes VALUES(1,?)", state.Route.DefaultOutbound); err != nil {
		return err
	}
	networkDocument, err := json.Marshal(state.Network)
	if err != nil {
		return identity.Err(identity.Invalid, "invalid canonical network configuration")
	}
	if err = w.exec("UPDATE client_network_profiles SET document=? WHERE singleton=1", string(networkDocument)); err != nil {
		return err
	}
	return w.exec("UPDATE client_profiles SET enabled=? WHERE singleton=1", state.Enabled)
}
