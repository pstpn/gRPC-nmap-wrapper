package config

import (
	"github.com/spf13/viper"
)

const (
	configFile = "./config/config.yaml"
)

type Config struct {
	App    AppConfig    `yaml:"app"`
	Server ServerConfig `yaml:"server"`
	Logger LoggerConfig `yaml:"logger"`
}

type AppConfig struct {
	Name    string `yaml:"name"`
	Version string `yaml:"version"`
}

type ServerConfig struct {
	Network string `env-required:"true" yaml:"network" env:"APP_NETWORK"`
	Port    int    `env-required:"true" yaml:"port" env:"APP_PORT"`
}

type LoggerConfig struct {
	Level string `yaml:"log_level" env:"LOG_LEVEL" env-default:"info"`
}

func NewConfig() (*Config, error) {

	var err error
	var config Config

	viper.SetConfigFile(configFile)
	err = viper.ReadInConfig()
	if err != nil {
		return nil, err
	}
	err = viper.Unmarshal(&config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}
