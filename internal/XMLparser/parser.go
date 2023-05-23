package XMLparser

import (
	"fmt"
	"strconv"

	"github.com/Ullaakut/nmap/v3"
	"github.com/gRPC-nmap-wrapper/internal/server/api"
)

func ParseVulns(hosts []nmap.Host) []*api.TargetResult {

	var results []*api.TargetResult

	for _, host := range hosts {
		results = append(results, parseTargets(&host))
	}

	return results
}

func parseTargets(host *nmap.Host) *api.TargetResult {

	targetResult := &api.TargetResult{
		Target:   host.Addresses[0].String(),
		Services: make([]*api.Service, 0, len(host.Ports)),
	}

	for _, port := range host.Ports {
		targetResult.Services = append(targetResult.Services, &api.Service{
			Name:    port.Service.Name,
			Version: port.Service.Version,
			TcpPort: int32(port.ID),
			Vulns:   parseServices(&port),
		})
	}

	return targetResult
}

func parseServices(port *nmap.Port) []*api.Vulnerability {

	var vulns []*api.Vulnerability

	for _, script := range port.Scripts {
		for _, table := range script.Tables {
			for _, subTable := range table.Tables {
				vuln, err := parseVuln(&subTable)
				if err == nil {
					vulns = append(vulns, vuln)
				}
			}
		}
	}

	return vulns
}

func parseVuln(table *nmap.Table) (*api.Vulnerability, error) {

	vuln := &api.Vulnerability{
		CvssScore: -1,
	}
	err := fmt.Errorf("no vulns")

	for _, element := range table.Elements {
		if element.Key == "id" {
			vuln.Identifier = element.Value
		} else if element.Key == "cvss" {
			cvss, _ := strconv.ParseFloat(element.Value, 32)
			vuln.CvssScore = float32(cvss)
		}
		if vuln.Identifier != "" && vuln.CvssScore != -1 {
			err = nil
			break
		}
	}

	return vuln, err
}
