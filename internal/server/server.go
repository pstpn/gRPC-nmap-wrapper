package server

import (
	"context"
	"fmt"
	"github.com/Ullaakut/nmap/v3"
	"github.com/gRPC-nmap-wrapper/pkg/api"
	"log"
	"time"
)

type GRPCServer struct{}

func (s *GRPCServer) CheckVuln(ctx context.Context, req *api.CheckVulnRequest) (*api.CheckVulnResponse, error) {

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Equivalent to `/usr/local/bin/nmap -p 80,443,843 google.com facebook.com youtube.com`,
	// with a 5-minute timeout.

	ports := ""
	for _, port := range req.GetTcpPort() {
		ports += fmt.Sprintf("%d, ", port)
	}

	scanner, err := nmap.NewScanner(
		ctx,
		nmap.WithTargets(req.GetTargets()...),
		nmap.WithPorts(ports[:len(ports)-2]),
	)
	if err != nil {
		log.Fatalf("unable to create nmap scanner: %v", err)
	}

	result, warnings, err := scanner.Run()
	if len(*warnings) > 0 {
		log.Printf("run finished with warnings: %s\n", *warnings) // Warnings are non-critical errors from nmap.
	}
	if err != nil {
		log.Fatalf("unable to run nmap scan: %v", err)
	}

	results := &api.CheckVulnResponse{
		Results: make([]*api.TargetResult, 0, len(req.GetTargets())),
	}

	// Use the results to print an example output
	for _, host := range result.Hosts {

		targetResult := &api.TargetResult{
			Target:   host.Addresses[0].String(),
			Services: make([]*api.Service, 0, len(host.Ports)),
		}

		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}

		for _, port := range host.Ports {
			targetResult.Services = append(targetResult.Services, &api.Service{
				Name:    port.Service.Name,
				Version: port.Service.Version,
				TcpPort: int32(port.ID),
				Vulns: []*api.Vulnerability{
					{
						Identifier: port.State.State,
						CvssScore:  0,
					},
				},
			})
		}

		results.Results = append(results.Results, targetResult)
	}

	return results, nil
}
