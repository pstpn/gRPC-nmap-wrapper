package server

import "github.com/gRPC-nmap-wrapper/pkg/logger"

type GRPCServer struct {
	logger logger.Interface
}

func NewServer(lg logger.Interface) *GRPCServer {
	return &GRPCServer{
		logger: lg,
	}
}
