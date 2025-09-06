//go:build linux
// +build linux

package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/cilium/ebpf/rlimit"
	"github.com/myserver/go-server/ebpf/internal/ebpf"
	"github.com/myserver/go-server/ebpf/internal/monitor"
)

func main() {
	var (
		pid   int
		name  string
		addr  string
		serve string
	)

	root := &cobra.Command{
		Use:   "http-monitor",
		Short: "Monitor HTTP requests of a given process using eBPF",
		RunE: func(cmd *cobra.Command, args []string) error {

			// Allow monitoring all processes if neither pid nor name is specified
			if pid == 0 && name == "" {
				log.Printf("No --pid or --name specified, monitoring ALL processes")
			}

			log.Printf("Starting HTTP monitor for selector: PID=%d, Name=%s", pid, name)
			selector := monitor.ProcessSelector{PID: pid, Name: name}

			// SSE hub
			type subscriber chan []byte
			var (
				mu   sync.RWMutex
				subs = map[subscriber]struct{}{}
			)

			broadcast := func(b []byte) {
				log.Printf("Broadcasting event to %d subscribers, event length=%d bytes", len(subs), len(b))
				mu.RLock()
				for ch := range subs {
					select {
					case ch <- b:
					default:
					}
				}
				mu.RUnlock()
			}

			// Lift memlock rlimit to allow larger BPF maps (e.g., 8MB ring buffer)
			if err := rlimit.RemoveMemlock(); err != nil {
				log.Printf("failed to remove memlock rlimit: %v", err)
			}
			// Start eBPF monitor
			log.Printf("Loading eBPF program...")
			prog, err := ebpf.NewHTTPMonitor(selector, broadcast)
			if err != nil {
				return fmt.Errorf("failed to create HTTP monitor: %w", err)
			}
			defer prog.Close()
			log.Printf("eBPF program loaded and attached successfully")

			// HTTP server
			mux := http.NewServeMux()
			if serve != "" {
				fs := http.FileServer(http.Dir(serve))
				mux.Handle("/", fs)
			}
			mux.HandleFunc("/events-sse", func(w http.ResponseWriter, r *http.Request) {
				log.Printf("New SSE client connected from %s", r.RemoteAddr)
				w.Header().Set("Content-Type", "text/event-stream")
				w.Header().Set("Cache-Control", "no-cache")
				w.Header().Set("Connection", "keep-alive")
				flusher, ok := w.(http.Flusher)
				if !ok {
					http.Error(w, "stream unsupported", 500)
					return
				}
				ch := make(subscriber, 64)
				mu.Lock()
				subs[ch] = struct{}{}
				mu.Unlock()
				defer func() {
					mu.Lock()
					delete(subs, ch)
					mu.Unlock()
					log.Printf("SSE client disconnected from %s, remaining: %d", r.RemoteAddr, len(subs))
				}()
				log.Printf("SSE client registered, total subscribers: %d", len(subs))
				// heartbeat (periodic comment to keep connection alive)
				go func() {
					for {
						select {
						case <-r.Context().Done():
							return
						default:
						}
						w.Write([]byte("\n"))
						flusher.Flush()
						<-time.After(25 * time.Second)
					}
				}()
				for {
					select {
					case <-r.Context().Done():
						return
					case msg := <-ch:
						log.Printf("Sending SSE message, length=%d bytes", len(msg))
						fmt.Fprintf(w, "data: %s\n\n", msg)
						flusher.Flush()
					}
				}
			})

			server := &http.Server{Addr: addr, Handler: mux}
			go func() {
				log.Printf("Serving SSE at http://%s/events-sse", addr)
				if serve != "" {
					log.Printf("Serving UI from %s at http://%s/", serve, addr)
				}
				if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					log.Printf("http server error: %v", err)
				}
			}()

			// Handle Ctrl+C
			c := make(chan os.Signal, 1)
			signal.Notify(c, os.Interrupt, syscall.SIGTERM)
			<-c
			log.Println("Shutting down...")
			server.Close()
			return nil
		},
	}

	root.Flags().IntVar(&pid, "pid", 0, "Process ID to monitor")
	root.Flags().StringVar(&name, "name", "", "Process name to monitor")
	root.Flags().StringVar(&addr, "addr", "0.0.0.0:8080", "HTTP listen address for SSE/UI")
	root.Flags().StringVar(&serve, "serve", "web", "Directory to serve as static UI (index.html)")

	if err := root.Execute(); err != nil {
		log.Fatal(err)
	}
}
