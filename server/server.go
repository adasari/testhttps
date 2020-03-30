package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"
)

func tlsDial(serverName string, ssl *SSLCertificate) grpc.DialOption {
	clientCreds := credentials.NewTLS(&tls.Config{
		ServerName:   serverName,
		Certificates: []tls.Certificate{ssl.Certificate},
		RootCAs:      ssl.CertPool,
	})

	return grpc.WithTransportCredentials(clientCreds)
}

// LoadSSLCertificates .
func LoadSSLCertificates(ssl *TLSConfig) (*SSLCertificate, error) {
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

	return &SSLCertificate{Certificate: certificate, CertPool: certPool}, nil
}

type TLSConfig struct {
	ServerName string
	CertFile   string
	KeyFile    string
	CAFile     string
}

// SSLCertificate holds TLS certificates for the client.
type SSLCertificate struct {
	Certificate tls.Certificate
	CertPool    *x509.CertPool
}

// Address holds server running ports.
type Address struct {
	GRPCPort int
	HTTPPort int
}

// Server holds gRPC server and HTTP REST gateway.
type Server struct {
	GRPCServer *grpc.Server
	Gateway    *RESTGateway
	Listener   net.Listener
	Address    Address
	TLSConfig  *TLSConfig
	Context    context.Context
}

// RESTGateway holds HTTP REST gateway server.
type RESTGateway struct {
	HTTPServer  *http.Server
	Listener    net.Listener
	ServeMux    *runtime.ServeMux
	HTTPMux     *http.ServeMux
	DialOptions []grpc.DialOption
	Endpoint    string
}

// ServerOption .
type ServerOption func(*Server) error

// WithTLS applies TLSConfig to server.
func WithTLS(c *TLSConfig) ServerOption {
	return func(s *Server) error {
		s.TLSConfig = c
		return nil
	}
}

// WithContext applies context to server.
func WithContext(c context.Context) ServerOption {
	return func(s *Server) error {
		s.Context = c
		return nil
	}
}

func New(addr Address, options ...ServerOption) (*Server, error) {
	// disallow port 0 in Listen - can't let OS pick random port, as it would
	// be impossible to map to a container.
	if addr.GRPCPort <= 0 || addr.HTTPPort <= 0 {
		return nil, fmt.Errorf("invalid TCP port for gRPC or HTTP server: %v, %v", addr.GRPCPort, addr.HTTPPort)
	}

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", addr.GRPCPort))
	if err != nil {
		return nil, fmt.Errorf("failed to listen port %d: %v", addr.GRPCPort, err)
	}

	log.Printf("creating gRPC server on %d", addr.GRPCPort)

	// creating a server with default context.
	srv := &Server{Address: addr, Listener: listener, Context: context.Background()}

	// applying all ServerOptions provided to server.
	for _, o := range options {
		if err := o(srv); err != nil {
			return nil, err
		}
	}

	var opts []grpc.ServerOption
	var sslCerts *SSLCertificate

	if srv.TLSConfig != nil {
		log.Printf("enabling TLS/SSL for gRPC server")

		sslCerts, err = LoadSSLCertificates(srv.TLSConfig)
		if err != nil {
			listener.Close()
			return nil, err
		}

		opts = append(opts, sslOpt(srv.TLSConfig.ServerName, sslCerts))
	}

	gRPCServer := grpc.NewServer(opts...)
	reflection.Register(gRPCServer)

	gateway, err := newGateway(srv.Address, srv.TLSConfig, sslCerts)
	if err != nil {
		listener.Close()
		return nil, fmt.Errorf("failed to create http gateway: %v", err)
	}

	srv.GRPCServer = gRPCServer
	srv.Gateway = gateway
	return srv, nil
}

func (s *Server) Run() error {
	if len(s.GRPCServer.GetServiceInfo()) <= 1 {
		log.Printf("no gRPC services are registered on server")
	}

	go func() {
		log.Printf("starting http gateway on %d ", s.Address.HTTPPort)

		defer s.Shutdown()
		if err := s.Gateway.HTTPServer.Serve(s.Gateway.Listener); err != nil {
			log.Printf("failed to start http gateway on %d: %v", s.Address.HTTPPort, err)
		}
	}()

	log.Printf("starting gRPC server on %d", s.Address.GRPCPort)
	if err := s.GRPCServer.Serve(s.Listener); err != nil {
		return fmt.Errorf("failed to start gRPC server on %d: %v", s.Address.GRPCPort, err)
	}

	return nil
}

func (s *Server) Shutdown() error {
	log.Printf("shutting down server")
	s.GRPCServer.Stop()
	if err := s.Gateway.HTTPServer.Close(); err != nil {
		return fmt.Errorf("failed to close gateway: %v", err)
	}

	return nil
}
