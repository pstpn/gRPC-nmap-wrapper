package xmlparser

import (
	"strconv"

	"github.com/Ullaakut/nmap/v3"
	"github.com/gRPC-nmap-wrapper/internal/server/api"
)

func ParseVulns(nmapResult *nmap.Run) []*api.TargetResult {

	var results []*api.TargetResult

	for _, host := range nmapResult.Hosts {
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
				vuln, vulnFound := parseVuln(&subTable)
				if vulnFound {
					vulns = append(vulns, vuln)
				}
			}
		}
	}

	return vulns
}

func parseVuln(table *nmap.Table) (*api.Vulnerability, bool) {

	vulnFound := false
	vuln := &api.Vulnerability{
		CvssScore: -1,
	}

	for _, element := range table.Elements {
		if element.Key == "id" {
			vuln.Identifier = element.Value
		} else if element.Key == "cvss" {
			cvss, _ := strconv.ParseFloat(element.Value, 32)
			vuln.CvssScore = float32(cvss)
		}
	}
	if vuln.Identifier != "" && vuln.CvssScore != -1 {
		vulnFound = true
	}

	return vuln, vulnFound
}
