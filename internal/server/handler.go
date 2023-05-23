package server

import (
	"context"
	"fmt"
	"strings"

	"github.com/Ullaakut/nmap/v3"
	"github.com/gRPC-nmap-wrapper/internal/XMLparser"
	"github.com/gRPC-nmap-wrapper/internal/server/api"
)

type GRPCServer struct{}

func (s *GRPCServer) CheckVuln(ctx context.Context, req *api.CheckVulnRequest) (*api.CheckVulnResponse, error) {

	ports := ""
	for _, port := range req.GetTcpPort() {
		ports += fmt.Sprintf("%d, ", port)
	}

	scanner, err := nmap.NewScanner(
		ctx,
		nmap.WithTargets(req.GetTargets()...),
		nmap.WithPorts(strings.TrimSuffix(ports, ", ")),
		nmap.WithCustomArguments("-sV"),
		nmap.WithScripts("vulners"),
	)
	if err != nil {
		return nil, err
	}

	nmapResult, _, err := scanner.Run()
	if err != nil {
		return nil, err
	}

	return &api.CheckVulnResponse{
		Results: XMLparser.ParseVulns(nmapResult.Hosts),
	}, nil
}
