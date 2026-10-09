package streamtransport

import "net/url"

// Query is the deliberately bounded common VLESS/Trojan share dialect.
func Query(q url.Values) (Config, error) {
	for _, key := range []string{"type", "path", "host", "serviceName"} {
		if values, present := q[key]; present && (len(values) != 1 || key == "type" && values[0] == "") {
			return Config{}, bad()
		}
	}
	c := Config{Kind: q.Get("type"), Path: q.Get("path"), Host: q.Get("host"), ServiceName: q.Get("serviceName")}
	if c.Kind == "" {
		c.Kind = "tcp"
	}
	if e := c.Validate(); e != nil {
		return Config{}, e
	}
	return c, nil
}
func (c Config) PutQuery(q url.Values) error {
	if e := c.Validate(); e != nil {
		return e
	}
	if len(c.Headers) > 0 {
		return bad()
	}
	q.Set("type", c.Type())
	if c.Type() == "ws" || c.Type() == "httpupgrade" {
		q.Set("path", c.HTTPPath())
		if c.Host != "" {
			q.Set("host", c.Host)
		}
	}
	if c.Type() == "grpc" {
		q.Set("serviceName", c.Service())
		if c.Host != "" {
			return bad()
		}
	}
	return nil
}
