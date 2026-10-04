//go:build linux || windows

package hostnetwork

import "errors"

// CloseOwnedDevice releases only a descriptor returned by this process's create.
// It never guesses an interface identity or deletes an OS object by name. This
// also releases a partial candidate when readback/journaling failed before an
// interface index was acknowledged; its journal remains available for recovery.
func (p *Platform) CloseOwnedDevice(name string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	device := p.devices[name]
	if device == nil {
		return nil
	}
	err := device.Close()
	if err == nil {
		delete(p.devices, name)
	}
	return err
}

func (p *Platform) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	var err error
	for name, device := range p.devices {
		e := device.Close()
		err = errors.Join(err, e)
		if e == nil {
			delete(p.devices, name)
		}
	}
	return err
}
