package spiffe

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

const (
	defaultSocketPath = "/tmp/spire-agent/public/api.sock"
)

// -------------------------------------------------------------------------------------------------
// Call the SPIRE Workload API over UDS or TCP socket...
// -------------------------------------------------------------------------------------------------
func getSpiffeSourceOption(w io.Writer, opts map[string]interface{}) (workloadapi.SourceOption, error) {

	var socket_addr string

	if *(opts["socketAddr"].(*string)) != "" {

		slices := strings.Split(*(opts["socketAddr"].(*string)), ":")
		if len(slices) != 2 {
			return nil, fmt.Errorf("socketAddr must be in the form of IP:PORT or :PORT")
		}
		if slices[1] == "" {
			return nil, fmt.Errorf("socketAddr must contain port value, in the form of IP:PORT or :PORT")
		}
		if slices[0] == "" {
			slices[0] = "127.0.0.1"
		}
		socket_addr = "tcp://" + slices[0] + ":" + slices[1]

	} else if *(opts["socketPath"].(*string)) != "" {
		socket_addr = "unix://" + *(opts["socketPath"].(*string))

	} else {
		socket_addr = "unix://" + defaultSocketPath
	}

	fmt.Fprintf(w, "--> GetSpiffeSourceOption(): Calling Workload API with socket_addr = %s\n", socket_addr)

	return workloadapi.WithClientOptions(workloadapi.WithAddr(socket_addr)), nil
}

// -------------------------------------------------------------------------------------------------
// Handle x509 SVID operations...
// -------------------------------------------------------------------------------------------------
func Fetchx509(ctx context.Context, opts map[string]interface{}) (string, error) {

	var w io.Writer
	if *(opts["verbose"].(*bool)) == true {
		w = os.Stderr
	} else {
		w = io.Discard
	}

	clientOptions, _ := getSpiffeSourceOption(w, opts)

	fmt.Fprintf(w, "--> Fetchx509(): Calling NewX509Source()...\n")
	x509Source, err := workloadapi.NewX509Source(ctx, clientOptions)
	if err != nil {
		return "", fmt.Errorf("unable to create x509source: %w", err)
	}
	defer x509Source.Close()

	fmt.Fprintf(w, "--> Fetchx509(): Calling GetX509SVID()...\n")
	svid, err := x509Source.GetX509SVID()
	if err != nil {
		return "", fmt.Errorf("unable to fetch xsvid: %w", err)
	}
	fmt.Fprintf(w, "--> Fetchx509(): Got SVID:\n")

	requested_cert := strings.ToLower(*(opts["dumpcert"].(*string)))
	outform := strings.ToLower(*(opts["outform"].(*string)))

	if *(opts["dumpkey"].(*bool)) == true {

		_, keyBytes, _ := svid.MarshalRaw() // to DER

		if outform == "pem" {
			pem.Encode(os.Stdout, &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
		} else if outform == "der" {
			binary.Write(os.Stdout, binary.LittleEndian, keyBytes)
		} else {
			return "", fmt.Errorf("no such cert format \"%s\"", outform)
		}

	} else if requested_cert == "all" {
		for _, cert := range svid.Certificates[0:] {
			if outform == "pem" {
				pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
			} else if outform == "der" {
				binary.Write(os.Stdout, binary.LittleEndian, cert.Raw)
			} else {
				return "", fmt.Errorf("no such cert format \"%s\"", outform)
			}
		}

	} else if requested_cert != "" {
		n, err := strconv.Atoi(requested_cert)
		if err != nil || n < 0 || n > len(svid.Certificates)-1 {
			return "", fmt.Errorf("cannot find cert \"%s\"", requested_cert)
		}

		if outform == "pem" {
			pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: svid.Certificates[n].Raw})
		} else if outform == "der" {
			binary.Write(os.Stdout, binary.LittleEndian, svid.Certificates[n].Raw)
		} else {
			return "", fmt.Errorf("no such cert format \"%s\"", outform)
		}

	} else if *(opts["dumpbundle"].(*bool)) == true {

		fmt.Fprintf(w, "--> Fetchx509(): Calling NewBundleSource()...\n")
		BundleSource, err := workloadapi.NewBundleSource(ctx, clientOptions)
		if err != nil {
			return "", fmt.Errorf("unable to create x509source: %w", err)
		}
		defer BundleSource.Close()

		fmt.Fprintf(w, "--> Fetchx509(): Calling GetX509BundleForTrustDomain() for\"%s\"...\n", svid.ID.TrustDomain())
		bundle, err := BundleSource.GetX509BundleForTrustDomain(svid.ID.TrustDomain())
		if err != nil {
			return "", fmt.Errorf("unable to fetch bundle: %w", err)
		}
		fmt.Fprintf(w, "--> Fetchx509(): Got Bundle:\n")

		bundleBytes, _ := bundle.Marshal() // to PEM

		var block *pem.Block
		block, _ = pem.Decode([]byte(bundleBytes))
		if block == nil {
			return "", fmt.Errorf("failed to decode PEM data for bundle: %w", err)
		}

		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return "", fmt.Errorf("failed to decode PEM data for bundle: not a certifcate: %w", err)
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return "", fmt.Errorf("failed to parse certificate data for bundle: %w", err)
		}

		if outform == "pem" {
			// fmt.Printf("%s", bundleBytes)  // IS the PEM; we got this from .Marshall()...
			pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		} else if outform == "der" {
			// binary.Write(os.Stdout, binary.LittleEndian, block.Bytes)  // IS the DER; we got this from pem.Decode()...
			binary.Write(os.Stdout, binary.LittleEndian, cert.Raw)
		} else {
			return "", fmt.Errorf("no such cert format \"%s\"", outform)
		}

	} else {
		fmt.Printf("- SPIFFE ID = %s\n", svid.ID.String())
		fmt.Printf("- TrustDomain = %s\n", svid.ID.TrustDomain().String())

		for i, cert := range svid.Certificates[0:] {
			fmt.Printf("- Cert[%d] Subject = %s\n", i, cert.Subject)
			fmt.Printf("- Cert[%d] Issuer = %s\n", i, cert.Issuer)
		}
	}

	return "blah", err
}

// -------------------------------------------------------------------------------------------------
// Handle JWT SVID operations...
// -------------------------------------------------------------------------------------------------
func FetchJWT(ctx context.Context, opts map[string]interface{}) (string, error) {

	var w io.Writer
	if *(opts["verbose"].(*bool)) == true {
		w = os.Stderr
	} else {
		w = io.Discard
	}

	clientOptions, _ := getSpiffeSourceOption(w, opts)

	fmt.Fprintf(w, "--> FetchJWT(): Calling NewJWTSource()...\n")
	jwtSource, err := workloadapi.NewJWTSource(ctx, clientOptions)
	if err != nil {
		return "", fmt.Errorf("unable to create jwtsource: %w", err)
	}
	defer jwtSource.Close()

	fmt.Fprintf(w, "--> FetchJWT(): Calling FetchJWTSVID()...\n")
	svid, err := jwtSource.FetchJWTSVID(ctx, jwtsvid.Params{
		Audience: *(opts["audience"].(*string)),
	})
	if err != nil {
		return "", fmt.Errorf("unable to fetch svid: %w", err)
	}
	fmt.Fprintf(w, "--> FetchJWT(): Got SVID:\n")

	if *(opts["dumpbundle"].(*bool)) == true {

		fmt.Fprintf(w, "--> FetchJWT(): Calling NewBundleSource()...\n")
		BundleSource, err := workloadapi.NewBundleSource(ctx, clientOptions)
		if err != nil {
			return "", fmt.Errorf("unable to create x509source: %w", err)
		}
		defer BundleSource.Close()

		fmt.Fprintf(w, "--> FetchJWT(): Calling GetJWTBundleForTrustDomain() for\"%s\"...\n", svid.ID.TrustDomain())
		bundle, err := BundleSource.GetJWTBundleForTrustDomain(svid.ID.TrustDomain())
		if err != nil {
			return "", fmt.Errorf("unable to fetch bundle: %w", err)
		}
		fmt.Fprintf(w, "--> FetchJWT(): Got Bundle:\n")

		bundleBytes, _ := bundle.Marshal() // to PEM
		fmt.Printf("%s\n", bundleBytes)

	} else if *(opts["dumpjwthdr"].(*bool)) == true {
		slices := strings.Split(svid.Marshal(), ".")
		data, _ := base64.RawURLEncoding.DecodeString(slices[0])
		fmt.Printf("%s\n", data)

	} else if *(opts["dumpjwtpay"].(*bool)) == true {
		slices := strings.Split(svid.Marshal(), ".")
		data, _ := base64.RawURLEncoding.DecodeString(slices[1])
		fmt.Printf("%s\n", data)

	} else if *(opts["dumpjwtsig"].(*bool)) == true {
		slices := strings.Split(svid.Marshal(), ".")
		data, _ := base64.RawURLEncoding.DecodeString(slices[2])
		binary.Write(os.Stdout, binary.LittleEndian, data)

	} else {
		fmt.Printf("%s\n", svid.Marshal())
	}

	return svid.Marshal(), nil
}
