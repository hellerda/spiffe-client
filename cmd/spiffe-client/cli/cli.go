package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"spiffe-client/pkg/spiffe"
)

type CliOpts map[string]interface{}

func RunCli(opts CliOpts) error {

	var w io.Writer
	if *(opts["verbose"].(*bool)) == true {
		w = os.Stderr
	} else {
		w = io.Discard
	}

	ctx := context.Background()

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	fmt.Fprintf(w, "--> RunCli(): Got context.\n")

	switch strings.ToLower(*(opts["fetch"].(*string))) {
	case "x509":
		fmt.Fprintf(w, "--> RunCli(): Calling Fetchx509()...\n")
		_, err := spiffe.Fetchx509(ctx, opts)
		if err != nil {
			return err
		}
	case "jwt":
		fmt.Fprintf(w, "--> RunCli(): Calling FetchJWT() with audience = %s.\n", *(opts["audience"].(*string)))
		_, err := spiffe.FetchJWT(ctx, opts)
		if err != nil {
			return err
		}
	default:
		fmt.Fprintf(w, "I don't know how to fetch a \"%s\" SVID :-(.\n", *(opts["fetch"].(*string)))
	}

	return nil
}
