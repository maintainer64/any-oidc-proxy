package main

import (
	"log"

	"github.com/joho/godotenv"
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
	app, err := newApp(config)
	if err != nil {
		log.Fatal(err)
	}
	app.Start()
}
