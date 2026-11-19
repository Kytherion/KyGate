//go:build !windows && !linux

package main

import "errors"

// Other systems: 'kygate service' is not available; 'kygate serve' runs
// under the system's own service manager (launchd on macOS, for example).

const (
	defaultServiceName = "kygate"
	serviceSupported   = false
)

var errNoService = errors.New("'kygate service' supports Windows and Linux")

func serviceKind() string                                    { return "not available on this system" }
func logHint(*serviceConfig) string                          { return "" }
func registerService(*serviceConfig) error                   { return errNoService }
func unregisterService(*serviceConfig) error                 { return errNoService }
func startService(*serviceConfig) error                      { return errNoService }
func stopService(*serviceConfig) error                       { return errNoService }
func serviceState(*serviceConfig) (registered, running bool) { return false, false }
func runService(*serviceConfig) error                        { return errNoService }
func superviseService(*serviceConfig) error                  { return errNoService }
func persistentEnv(string) bool                              { return false }
