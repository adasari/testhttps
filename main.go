package main

import (
	"context"
	"log"
	"os"
	
	"github.com/adasari/testhttps/server"
	"github.com/adasari/testhttps/service"
	"github.com/spf13/pflag"

	testpb "github.com/adasari/testhttps/proto/v1"
)

func main() {

	cn := pflag.StringP("cn", "s", "", "CN name")
	ca := pflag.StringP("ca", "c", "", "CA file")
	key := pflag.StringP("key", "k", "", "Key file")
	crt := pflag.StringP("crt", "r", "", "CRT file")

	pflag.Parse()

	log.Printf("cn : %v", *cn)
	log.Printf("ca : %v", *ca)
	log.Printf("key : %v", *key)
	log.Printf("crt : %v", *crt)

	srvAddr := server.Address{
		GRPCPort: 9090,
		HTTPPort: 8080,
	}

	/* tlsConfig := &server.TLSConfig{
		ServerName: *cn,
		CertFile:   *crt,
		KeyFile:    *key,
		CAFile:     *ca,
	} */

	serverOpts := []server.ServerOption{server.WithContext(context.Background())}
	//serverOpts = append(serverOpts, server.WithTLS(tlsConfig))

	srv, err := server.New(srvAddr, serverOpts...)
	if err != nil {
		log.Printf("failed to create server %v", err)
		os.Exit(1)
	}

	defer srv.Shutdown()

	testpb.RegisterGreeterServer(srv.GRPCServer, service.NewGreeterServer())
	testpb.RegisterGreeterHandlerFromEndpoint(srv.Context, srv.Gateway.ServeMux, srv.Gateway.Endpoint, srv.Gateway.DialOptions)
	//logpb.RegisterSearchServiceHandlerFromEndpoint(srv.Context, srv.Gateway.ServeMux, srv.Gateway.Endpoint, srv.Gateway.DialOptions)

	if err := srv.Run(); err != nil {
		log.Printf("%v", err)
	}

	/* v1Api := v1.NewGreeterServer()
	//return grpc.RunServer(ctx, v1Api, port)

	listen, err := net.Listen("tcp", ":"+port)
	if err != nil {
		return err
	}

	// register service
	server := grpc.NewServer()
	apiv1.RegisterGreeterServer(server, v1Api)

	// start gRPC server
	log.Println("starting gRPC server at localhost:", port)
	return server.Serve(listen) */
}
