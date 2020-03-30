package server

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"google.golang.org/grpc"
)

func CustomMatcher(key string) (string, bool) {
	var newKey string
	var flag bool
	switch key {
	case "x-custom-header":
		newKey, flag = key, true
		//return key, true
	default:
		newKey, flag = runtime.DefaultHeaderMatcher(key)
	}

	fmt.Printf("headers: key %s , newKey: %s\n", key, newKey)

	return newKey, flag
}

// newGateway creates and returns a HTTP gateway instance with the given configuration.
// if http gateway cannot be created an error will be returned.
func newGateway(addr Address, tlsConfig *TLSConfig, sslCerts *SSLCertificate) (*RESTGateway, error) {
	gRPCSrvAddr := fmt.Sprintf(":%d", addr.GRPCPort)
	gwAddr := fmt.Sprintf(":%d", addr.HTTPPort)

	log.Printf("creating gateway on %s (http), forwarding to %s (grpc)", gwAddr, gRPCSrvAddr)

	mux := http.NewServeMux()
	// gwmux := runtime.NewServeMux(runtime.WithMarshalerOption(runtime.MIMEWildcard, &runtime.JSONPb{OrigName:false}))
	gwmux := runtime.NewServeMux(runtime.WithIncomingHeaderMatcher(CustomMatcher))

	mux.Handle("/", gwmux)

	dialOpts := []grpc.DialOption{grpc.WithInsecure()}
	httpSrv := &http.Server{Addr: gwAddr, Handler: mux}

	listener, err := net.Listen("tcp", gwAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen %s: %v", gwAddr, err)
	}

	if tlsConfig != nil {
		log.Printf("enabling TLS/SSL for HTTP gateway")

		dialOpts = sslDial(tlsConfig.ServerName, sslCerts)
		httpSrv.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{sslCerts.Certificate},
			NextProtos:   []string{"h2"},
			RootCAs:      sslCerts.CertPool,
		}

		// create listener with TLS credentials.
		listener = tls.NewListener(listener, httpSrv.TLSConfig)
	}

	return &RESTGateway{
		HTTPServer:  httpSrv,
		Listener:    listener,
		ServeMux:    gwmux,
		HTTPMux:     mux,
		DialOptions: dialOpts,
		Endpoint:    gRPCSrvAddr,
	}, nil
}
