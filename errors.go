package tunneler

import "errors"

// ErrNotReady is returned by Tunnel.URL when the tunnel has not finished
// starting: there is no public endpoint to return yet. Callers should treat
// it as a "try again after Start succeeds" condition, not a fatal failure.
var ErrNotReady = errors.New("tunnel not ready")
