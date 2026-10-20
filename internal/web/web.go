// Package web holds the embedded single-page console served by the API server.
package web

import _ "embed"

// Index is the console HTML served at "/".
//
//go:embed index.html
var Index string
