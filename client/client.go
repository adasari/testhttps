package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	v1 "github.com/adasari/testhttps/proto/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// TLSConfig holds client TLS/SSL configurations to activate SSL support.
type TLSConfig struct {
	ServerName string
	CertFile   string
	KeyFile    string
	CAFile     string
}

// sslCertificate holds TLS certificates for the client.
type sslCertificate struct {
	certificate tls.Certificate
	certPool    *x509.CertPool
}

func main() {

	req := `{
		"message":"testing"
	}`

	addr := "localhost:8080"
	var tlsCfg *TLSConfig
	/* tls := &TLSConfig{
		ServerName: "test.testns.svc.cluster.local",
		CertFile:   "/Users/anilkd/poc-certs/out/test.testns.svc.cluster.local.crt",
		KeyFile:    "/Users/anilkd/poc-certs/out/test.testns.svc.cluster.local.key",
		CAFile:     "/Users/anilkd/poc-certs/out/test.testns.svc.cluster.local.crt",
	} */

	var resp *http.Response
	var err error
	var url string

	client := &http.Client{}

	if tlsCfg != nil {
		// https

		fmt.Println("enabling TLS/SSL for HTTP REST client")
		sslCerts, err := loadSSLCertificates(tlsCfg)
		if err != nil {
			fmt.Printf("%v\n", err)
			os.Exit(0)
		}

		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:   tlsCfg.ServerName,
				Certificates: []tls.Certificate{sslCerts.certificate},
				RootCAs:      sslCerts.certPool,
			},
		}

		// url = fmt.Sprintf("https://%s/v1/search", addr)
		url = fmt.Sprintf("https://%s/v1/search/stream", addr)
	} else {
		// http
		// url = fmt.Sprintf("http://%s/v1/search", addr)
		url = fmt.Sprintf("http://%s/v1/search", addr)
	}

	fmt.Printf("url: %v\n", url)

	/* jsonValue, err := json.MarshalIndent(req, "", "\t\t")
	if err != nil {
		fmt.Printf("%v\n", err)
		os.Exit(0)
	} */

	log.Printf("req: %v", req)

	resp, err = client.Post(url, "application/json", bytes.NewBuffer([]byte(req)))
	if err != nil {
		fmt.Printf("%v\n", err)
		os.Exit(0)
	}
	// read the response body.
	fmt.Printf("headers: %+v\n", resp.Header)
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("%v\n", err)
	}
	respStr := fmt.Sprintf("%s", body)
	fmt.Printf("response with HTTP client: %s\n", respStr)
}

func loadSSLCertificates(ssl *TLSConfig) (*sslCertificate, error) {
	serverName := strings.TrimSpace(ssl.ServerName)
	certFile := strings.TrimSpace(ssl.CertFile)
	keyFile := strings.TrimSpace(ssl.KeyFile)
	caFile := strings.TrimSpace(ssl.CAFile)

	if len(serverName) == 0 {
		return nil, fmt.Errorf("server name is missing/empty")
	}

	// load the server certificates from disk.
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load ssl certFile or keyFile: %v", err)
	}

	caBytes, err := ioutil.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read ca certificate %s: %v", caFile, err)
	}

	// create a certificate pool from the certificate authority(CA).
	certPool := x509.NewCertPool()

	// append the client certificates from the CA.
	ok := certPool.AppendCertsFromPEM(caBytes)
	if !ok {
		return nil, fmt.Errorf("failed to append client certificates, bad CA certificate")
	}

	return &sslCertificate{certificate: certificate, certPool: certPool}, nil
}

func tlsDial(serverName string, ssl *sslCertificate) grpc.DialOption {
	clientCreds := credentials.NewTLS(&tls.Config{
		ServerName:   serverName,
		Certificates: []tls.Certificate{ssl.certificate},
		RootCAs:      ssl.certPool,
	})

	return grpc.WithTransportCredentials(clientCreds)
}

// gRPC hit
func callGRPC(addr string) {
	dialOpts := grpc.WithInsecure()
	var tls *TLSConfig
	/* tls := &TLSConfig{
		ServerName: "test.testns.svc.cluster.local",
		CertFile:   "/Users/anilkd/poc-certs/out/test.testns.svc.cluster.local.crt",
		KeyFile:    "/Users/anilkd/poc-certs/out/test.testns.svc.cluster.local.key",
		CAFile:     "/Users/anilkd/poc-certs/out/test.testns.svc.cluster.local.crt",
	} */
	if tls != nil {
		sslCerts, err := loadSSLCertificates(tls)
		if err != nil {
			fmt.Printf("failed to load certificates: %v\n", err)
			os.Exit(1)
		}
		dialOpts = tlsDial(tls.ServerName, sslCerts)
	}
	conn, err := grpc.Dial(addr, dialOpts)
	if err != nil {
		fmt.Printf("could not dial: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	client := v1.NewGreeterClient(conn)
	log.Printf("Client connected to the server at address %v, and ready to  make grpc calls.", addr)

	resp, err := client.SayHello(context.Background(), &v1.HelloRequest{Message: "1232"})
	if err != nil {
		log.Fatalf("failed to start client: %v", err)

	}

	fmt.Printf("resp : %+v", resp)
}
