package oidc

import "log"

// Debug decides if echo should print message on console
var Debug = false

func echo(format string, in ...interface{}) {
	if !Debug {
		return
	}
	log.Printf(format, in...)
}
