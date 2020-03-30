package server

import (
	"crypto/tls"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// sslOpt returns gRPC ServerOption with TLS/SSL credentials.
func sslOpt(serverName string, sslCerts *SSLCertificate) grpc.ServerOption {
	serverCreds := credentials.NewTLS(&tls.Config{
		ServerName:   serverName,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{sslCerts.Certificate},
		ClientCAs:    sslCerts.CertPool,
	})

	return grpc.Creds(serverCreds)
}

// sslDial returns HTTP gateway DialOption with TLS/SSL credentials.
func sslDial(serverName string, sslCerts *SSLCertificate) []grpc.DialOption {
	gatewayCreds := credentials.NewTLS(&tls.Config{
		ServerName:   serverName,
		Certificates: []tls.Certificate{sslCerts.Certificate},
		RootCAs:      sslCerts.CertPool,
	})

	return []grpc.DialOption{grpc.WithTransportCredentials(gatewayCreds)}
}
