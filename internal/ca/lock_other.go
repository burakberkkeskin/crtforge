//go:build !unix

package ca

// lock is a no-op where flock is unavailable; crtforge is released for
// macOS and Linux only.
func lock(string) (func(), error) { return func() {}, nil }
