package main

import (
	"log"

	"github.com/gRPC-nmap-wrapper/config"
	"github.com/gRPC-nmap-wrapper/internal/app"
)

func main() {

	cfg, err := config.NewConfig()
	if err != nil {
		log.Fatalf("Config error: %s", err)
	}

	app.Run(cfg)
}
