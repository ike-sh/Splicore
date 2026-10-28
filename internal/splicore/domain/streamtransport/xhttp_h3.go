package streamtransport

// XHTTPH3 selects the HTTP/3 carrier only for an explicit, unambiguous ALPN.
func (c Config) XHTTPH3(alpn []string) bool {
	return c.Type() == "xhttp" && len(alpn) == 1 && alpn[0] == "h3"
}

// ValidateSecurity binds the carrier selector to its outer security policy.
func (c Config) ValidateSecurity(security string, alpn []string) error {
	if c.ValidateALPN(alpn) != nil || c.XHTTPH3(alpn) && security != "tls" {
		return bad()
	}
	return nil
}
