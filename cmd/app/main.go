package main

import (
	"log"

	"github.com/gRPC-nmap-wrapper/config"
	"github.com/gRPC-nmap-wrapper/internal/app"
	"github.com/gRPC-nmap-wrapper/pkg/logger"
)

func main() {

	cfg, err := config.NewConfig()
	if err != nil {
		log.Fatalf("Config error: %s", err)
	}
	l := logger.NewLogger(cfg.Logger.Level)

	app.Run(cfg, l)
}
