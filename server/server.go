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

// TLSConfig holds client TLS/SSL configurations to activate SSL support.
// TLSConfig holds server TLS/SSL configurations to activate SSL support.
type TLSConfig struct {
	// ServerName is the server for which certificates has been generated.
	ServerName string
	// CertFile is the file path for ssl cert file.
	CertFile string
	// KeyFile is the file path for ssl key file.
	KeyFile string
	// CAFile is the file path for ssl ca file.
	CAFile string
}

// SSLCertificate holds TLS certificates for the client.
type SSLCertificate struct {
	Certificate tls.Certificate
	CertPool    *x509.CertPool
}

// Address holds server running ports.
type Address struct {
	// GRPCPort is the listening port for GRPC service.
	GRPCPort int
	// HTTPPort is the listening port for HTTP service.
	HTTPPort int
}

// Server holds gRPC server and HTTP REST gateway.
// It implements Run and Shutdown for server.
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

// New creates a server instance with gRPC and HTTP REST gateway instances which
// has no service registered and has not started to accept requests yet.
// if TLSConfig is supplied then it creates a TLS/SSL security enabled server.
// else creates a server without TLS/SSL security.
// if the server cannot be created an error will be returned.
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

// Run starts a gRPC server and HTTP REST gateway to publish registered rpc services.
// It read gRPC requests and then call the registered handlers to reply to them.
// if the server cannot be started an error will be returned.
func (s *Server) Run() error {
	// check if apps has registered their services or not.
	// reflection service is already registered on gRPC server so minimum count is 1.
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

// Shutdown stops the gRPC server and http gateway. It immediately closes all open connections
// and listeners. It cancels all active RPCs on the server side and the corresponding
// pending RPCs on the client side will get notified by connection errors.
func (s *Server) Shutdown() error {
	log.Printf("shutting down server")
	s.GRPCServer.Stop()
	if err := s.Gateway.HTTPServer.Close(); err != nil {
		return fmt.Errorf("failed to close gateway: %v", err)
	}

	return nil
}
