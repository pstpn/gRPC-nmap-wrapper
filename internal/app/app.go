package app

import (
	"fmt"
	"google.golang.org/grpc"
	"net"

	"github.com/gRPC-nmap-wrapper/config"
	"github.com/gRPC-nmap-wrapper/internal/server"
	"github.com/gRPC-nmap-wrapper/internal/server/api"
	"github.com/gRPC-nmap-wrapper/pkg/logger"
)

func Run(cfg *config.Config, lg logger.Interface) {

	s := grpc.NewServer()
	srv := &server.GRPCServer{}
	api.RegisterNetVulnServiceServer(s, srv)

	address := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	l, err := net.Listen(cfg.Server.Network, address)
	if err != nil {
		lg.Error(fmt.Sprintf("app - Run - net.Listen: %e", err))
	}
	lg.Info(fmt.Sprintf("Server running on %s at %s", cfg.Server.Network, address))

	if err = s.Serve(l); err != nil {
		lg.Error(fmt.Sprintf("app - Run - Server.Serve: %e", err))
	}
}
