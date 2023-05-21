package main

import (
	"github.com/gRPC-nmap-wrapper/internal/server"
	"github.com/gRPC-nmap-wrapper/pkg/api"
	"google.golang.org/grpc"
	"log"
	"net"
)

func main() {

	s := grpc.NewServer()
	srv := &server.GRPCServer{}
	api.RegisterNetVulnServiceServer(s, srv)

	l, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatal(err)
	}

	if err = s.Serve(l); err != nil {
		log.Fatal(err)
	}
}
