package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/OpenStack-Policy-Agent/OSPA/pkg/discovery/services"
	_ "github.com/OpenStack-Policy-Agent/OSPA/pkg/services"
	_ "github.com/OpenStack-Policy-Agent/OSPA/pkg/services/services"
)

func main() {
	addr := flag.String("listen", ":8080", "HTTP listen address")
	defaultPolicy := flag.String("default-policy", "examples/policies.yaml", "Default policy path shown in the UI")
	flag.Parse()

	srv, err := newServer(*defaultPolicy)
	if err != nil {
		log.Fatalf("server init: %v", err)
	}

	httpServer := &http.Server{
		Addr:              *addr,
		Handler:           srv.routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		fmt.Printf("OSPA UI listening on http://localhost%s\n", *addr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %v", err)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(shutdownCtx)
}
