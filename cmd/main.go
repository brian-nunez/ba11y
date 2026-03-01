package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/brian-nunez/go-echo-starter-template/internal/httpserver"
)

func main() {
	server := httpserver.Bootstrap(httpserver.BootstrapConfig{
		StaticDirectories: map[string]string{
			"/assets": "./assets",
		},
	})

	PORT := os.Getenv("PORT")
	if PORT == "" {
		PORT = "8080"
	}

	go func() {
		err := server.Start(fmt.Sprintf(":%s", PORT))
		if err != nil && err.Error() != "http: Server closed" {
			log.Fatalf("could not start server: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	<-quit

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	log.Println("Shutting down server...")
	err := server.Shutdown(ctx)
	if err != nil {
		log.Fatalf("Server shutdown failed: %v", err)
	}
	log.Println("Server exited cleanly")
}
