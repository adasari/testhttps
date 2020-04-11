package service

import (
	"context"
	"log"
	"time"

	testpb "github.com/adasari/testhttps/proto/v1"
	"google.golang.org/grpc/metadata"
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

// SayHello implements apiv1.GreeterServer interface method
func (s *server) SayHelloStream(req *testpb.HelloRequest, stream testpb.Greeter_SayHelloStreamServer) error {
	log.Printf("Received the request msg: %v", req)
	header := metadata.Pairs("mykey", "val")
	stream.SendHeader(header)
	msgs := []*testpb.HelloReply{
		&testpb.HelloReply{Message: "Hello-1-" + req.Message, TestVal: "testvalue"},
		&testpb.HelloReply{Message: "Hello-2-" + req.Message, TestVal: "testvalue"},
		&testpb.HelloReply{Message: "Hello-3-" + req.Message, TestVal: "testvalue"},
	}

	for _, msg := range msgs {
		if err := stream.Send(msg); err != nil {
			return err
		}
		time.Sleep(5 * time.Second)
	}
	//return &testpb.HelloReply{Message: "Hello" + req.Message, TestVal: "testvalue"}, nil

	return nil
}
