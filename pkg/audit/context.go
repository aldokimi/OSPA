package audit

import "context"

type contextKey string

const clientContextKey contextKey = "ospa.service_client"

// WithClient stores a service client in ctx for auditors that need API calls
// during Check (e.g. Keystone role assignment enumeration).
func WithClient(ctx context.Context, client interface{}) context.Context {
	return context.WithValue(ctx, clientContextKey, client)
}

// ClientFromContext returns the service client previously stored with WithClient.
func ClientFromContext(ctx context.Context) (interface{}, bool) {
	if ctx == nil {
		return nil, false
	}
	v := ctx.Value(clientContextKey)
	if v == nil {
		return nil, false
	}
	return v, true
}
