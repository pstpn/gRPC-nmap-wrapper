package app

import (
	"fmt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"net"

	"github.com/gRPC-nmap-wrapper/config"
	"github.com/gRPC-nmap-wrapper/internal/server"
	"github.com/gRPC-nmap-wrapper/internal/server/api"
	"github.com/gRPC-nmap-wrapper/pkg/logger"
)

func Run(cfg *config.Config, lg logger.Interface) {

	s := grpc.NewServer()
	api.RegisterNetVulnServiceServer(s, server.NewServer(lg))
	reflection.Register(s)

	address := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	l, err := net.Listen(cfg.Server.Network, address)
	if err != nil {
		lg.Fatal(fmt.Sprintf("app - Run - net.Listen: %v", err.Error()))
	}
	lg.Info(fmt.Sprintf("Server running on %s at %s", cfg.Server.Network, address))

	if err = s.Serve(l); err != nil {
		lg.Fatal(fmt.Sprintf("app - Run - Server.Serve: %v", err.Error()))
	}
}
