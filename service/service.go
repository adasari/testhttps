package service

import (
	"context"
	"log"

	testpb "github.com/adasari/testhttps/proto/v1"
)

type server struct{}

// NewGreeterServer creates GreeterServer
func NewGreeterServer() testpb.GreeterServer {
	return &server{}
}

// SayHello implements apiv1.GreeterServer interface method
func (s *server) SayHello(ctx context.Context, req *testpb.HelloRequest) (*testpb.HelloReply, error) {
	log.Printf("Received the request msg: %v", req)
	return &testpb.HelloReply{Message: "Hello" + req.Message, TestVal: "testvalue"}, nil
}
