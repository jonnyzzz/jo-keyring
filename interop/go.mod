// Test tooling for the jo-keyring port: a CLI wrapper around the library being ported,
// pinned to the exact upstream commit that was ported.
module github.com/jonnyzzz/jo-keyring/interop

go 1.24

require github.com/zalando/go-keyring v0.2.9-0.20260724212736-66b55cc0c51c

require (
	github.com/danieljoos/wincred v1.2.3 // indirect
	github.com/godbus/dbus/v5 v5.2.2 // indirect
	golang.org/x/sys v0.27.0 // indirect
)
