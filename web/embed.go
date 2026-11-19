// Package web holds the console: static files embedded in the binary.
//
// The console is plain HTML, CSS, and JavaScript with no build step, so the
// Go binary builds without Node. It shows reports and, for signed-in roles,
// administration.
package web

import "embed"

// Static is the console, under static/.
//
//go:embed static
var Static embed.FS
