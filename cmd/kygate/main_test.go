package main

import "testing"

// A command whose flags are defined twice panics at run time: each command
// that takes the shared flags must parse.
func TestCommandFlagsDoNotClash(t *testing.T) {
	for name, run := range map[string]func([]string) error{"policy show": policyShow} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("%s: %v", name, r)
				}
			}()
			run([]string{"--data-dir", t.TempDir()})
		}()
	}
}
