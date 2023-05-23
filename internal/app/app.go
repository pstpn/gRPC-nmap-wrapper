package app

import (
	"github.com/gRPC-nmap-wrapper/internal/server/api"
	"google.golang.org/grpc"
	"log"
	"net"

	"github.com/gRPC-nmap-wrapper/config"
	"github.com/gRPC-nmap-wrapper/internal/server"
	"github.com/gRPC-nmap-wrapper/pkg/logger"
)

func Run(cfg *config.Config, lg *logger.Interface) {

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
