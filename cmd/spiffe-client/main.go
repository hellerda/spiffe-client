package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"spiffe-client/cmd/spiffe-client/cli"
)

func main() {

	var (
		socketPath  = flag.String("socketPath", "", "Path to the SPIRE Agent API socket (default: \"/tmp/spire-agent/public/api.sock\")")
		socketAddr  = flag.String("socketAddr", "", "TCP address to connect to the SPIRE Agent API, in the form of \"IP:PORT\"")
		audience    = flag.String("audience", "CI", "The audience to pass to the the JWT claim")
		fetch       = flag.String("fetch", "x509", "Fetch an x509 or JWT SVID from SPIRE")
		dumpkey     = flag.Bool("dumpkey", false, "for x509 SVID: Dump privkey to stdout")
		dumpcert    = flag.String("dumpcert", "", "for x509 SVID: Dump specified cert(s) to stdout")
		dumpbundle  = flag.Bool("dumpbundle", false, "for x509 SVID: Dump Bundle cert(s) to stdout")
		outform     = flag.String("outform", "PEM", "Output PEM or DER format for -dumpcert")
		dumpjwthdr  = flag.Bool("dumpjwthdr", false, "for JWT SVID: Dump the token header to stdout")
		dumpjwtpay  = flag.Bool("dumpjwtpay", false, "for JWT SVID: Dump the token payload to stdout")
		dumpjwtsig  = flag.Bool("dumpjwtsig", false, "for JWT SVID: Dump the (binary) token signature to stdout")
		verbose     = flag.Bool("v", false, "Show more details (verbose)")
	)
	flag.Parse()

	if *socketPath != "" && *socketAddr != "" {
		fmt.Printf("err: Conflicting options: -socketPath and -socketAddr\n")
		os.Exit(1)
	}

	var w io.Writer
	if *verbose {
		w = os.Stderr
	} else {
		w = io.Discard
	}

	s := strings.Builder{}
	t := tabwriter.NewWriter(&s, 0, 0, 2, ' ', 0)

	cli_opts := cli.CliOpts{
		"socketPath": socketPath,
		"socketAddr": socketAddr,
		"audience":   audience,
		"fetch":      fetch,
		"dumpkey":    dumpkey,
		"dumpcert":   dumpcert,
		"dumpbundle": dumpbundle,
		"outform":    outform,
		"dumpjwthdr": dumpjwthdr,
		"dumpjwtpay": dumpjwtpay,
		"dumpjwtsig": dumpjwtsig,
		"verbose":    verbose,
	}

	fmt.Fprintf(t, "--> main(): Flags are...\n"+
		"\t- audience\t%s\n"+
		"\t- socketPath\t%s\n"+
		"\t- socketAddr\t%s\n"+
		"\t- verbose\t%t\n",
		*(cli_opts["audience"].(*string)), *(cli_opts["socketPath"].(*string)), *(cli_opts["socketAddr"].(*string)), *(cli_opts["verbose"].(*bool)))
	t.Flush()
	fmt.Fprintf(w, s.String())

	err := cli.RunCli(cli_opts)
	if err != nil {
		fmt.Printf("err: %v\n", err)
	}

	os.Exit(0)
}
