package pac

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"
)

type Server struct {
	addr      string
	proxyAddr string
	server    *http.Server
	listener  net.Listener
}

func NewServer(addr, proxyAddr string) *Server {
	return &Server{addr: addr, proxyAddr: proxyAddr}
}

func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/proxy.pac", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
		_, _ = fmt.Fprintf(w, "function FindProxyForURL(url, host) { return \"PROXY %s; DIRECT\"; }", s.proxyAddr)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})

	s.server = &http.Server{
		Addr:              s.addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	listener, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	s.listener = listener

	go func() {
		_ = s.server.Serve(listener)
	}()
	return nil
}

func (s *Server) Stop(ctx context.Context) error {
	if s.server == nil || s.listener == nil {
		return nil
	}
	err := s.server.Shutdown(ctx)
	s.listener = nil
	return err
}

func (s *Server) URL() string {
	return "http://" + s.addr + "/proxy.pac"
}
