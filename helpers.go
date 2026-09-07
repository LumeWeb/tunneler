package tunneler

import (
	"fmt"
	"net"
	"strings"
)

// LocalURL builds an http:// origin from a host:port pair for a tunnel's
// upstream.
func LocalURL(host, port string) string {
	return "http://" + net.JoinHostPort(host, port)
}

// UrlForOrigin normalizes a host:port local address into the http:// URL used
// as the ingress service of a tunnel.
func UrlForOrigin(localAddr string) (string, error) {
	host, port, err := SplitHostPort(localAddr)
	if err != nil {
		return "", fmt.Errorf("invalid local address %q: %w", localAddr, err)
	}
	return "http://" + net.JoinHostPort(host, port), nil
}

// BareHostname strips a leading http(s):// scheme so hostname comparisons and
// provider ingress hosts are always bare (e.g. "mcp.example.com"), never
// scheme-qualified URLs. It also strips a trailing path/hash fragment if a
// caller passed a full URL.
func BareHostname(h string) string {
	h = strings.TrimSpace(h)
	for _, p := range []string{"https://", "http://"} {
		if len(h) >= len(p) && strings.EqualFold(h[:len(p)], p) {
			h = h[len(p):]
			break
		}
	}
	if i := strings.IndexAny(h, "/?#"); i >= 0 {
		h = h[:i]
	}
	return h
}
