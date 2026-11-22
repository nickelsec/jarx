//go:build !windows

package platform

// realRegistry is nil off Windows: there's no registry to read.
func realRegistry() Registry { return nil }
