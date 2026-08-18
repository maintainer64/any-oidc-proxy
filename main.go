package main

import (
	"github.com/joho/godotenv"
	log "github.com/sirupsen/logrus"
)

func init() {
	// loads values from .env into the system
	if err := godotenv.Load(); err != nil {
		log.Print("No .env file found")
	}
}

func main() {
	config, err := loadConfig()
	if err != nil {
		log.Fatal(err)
	}
	level, err := log.ParseLevel(config.LogLevel)
	if err != nil {
		log.Fatalf("Invalid log level specified: %v", err)
	}
	log.SetLevel(level)
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
	})
	app, err := newApp(config)
	if err != nil {
		log.Fatal(err)
	}
	app.Start()
}
