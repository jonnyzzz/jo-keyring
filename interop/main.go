// Command go-keyring-helper exposes zalando/go-keyring over a tiny CLI so that the Kotlin test
// suite can verify that jo-keyring and go-keyring read each other's secrets.
//
// This is test tooling for the port, not part of the published library.
//
// Secrets cross the process boundary base64 encoded, so that multi-line, non-ASCII and binary
// payloads are unaffected by shell quoting or console encoding.
//
// Exit codes: 0 success, 3 secret not found, 1 anything else.
package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"

	"github.com/zalando/go-keyring"
)

const exitNotFound = 3

func main() {
	if len(os.Args) < 2 {
		usage()
	}

	switch os.Args[1] {
	case "set":
		requireArgs(5, "set <service> <user> <base64-secret>")
		secret, err := base64.StdEncoding.DecodeString(os.Args[4])
		fatalIf(err, "the secret argument is not valid base64")
		fatalIf(keyring.Set(os.Args[2], os.Args[3], string(secret)), "set failed")

	case "get":
		requireArgs(4, "get <service> <user>")
		secret, err := keyring.Get(os.Args[2], os.Args[3])
		if errors.Is(err, keyring.ErrNotFound) {
			fmt.Fprintln(os.Stderr, "NOT_FOUND")
			os.Exit(exitNotFound)
		}
		fatalIf(err, "get failed")
		fmt.Println(base64.StdEncoding.EncodeToString([]byte(secret)))

	case "delete":
		requireArgs(4, "delete <service> <user>")
		err := keyring.Delete(os.Args[2], os.Args[3])
		if errors.Is(err, keyring.ErrNotFound) {
			fmt.Fprintln(os.Stderr, "NOT_FOUND")
			os.Exit(exitNotFound)
		}
		fatalIf(err, "delete failed")

	case "deleteall":
		requireArgs(3, "deleteall <service>")
		fatalIf(keyring.DeleteAll(os.Args[2]), "deleteall failed")

	case "listusers":
		requireArgs(3, "listusers <service>")
		users, err := keyring.ListUsers(os.Args[2])
		fatalIf(err, "listusers failed")
		for _, user := range users {
			fmt.Println(user)
		}

	default:
		usage()
	}
}

func requireArgs(count int, form string) {
	if len(os.Args) != count {
		fmt.Fprintf(os.Stderr, "usage: %s %s\n", os.Args[0], form)
		os.Exit(1)
	}
}

func fatalIf(err error, context string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", context, err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `usage: %s <command> [arguments]

  set <service> <user> <base64-secret>
  get <service> <user>                   prints the secret, base64 encoded
  delete <service> <user>
  deleteall <service>
  listusers <service>                    prints one user per line
`, os.Args[0])
	os.Exit(1)
}
