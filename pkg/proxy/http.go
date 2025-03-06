package proxy

import (
	"io"
	"net/http"
	"strings"

	"github.com/go-puzzles/puzzles/plog"
)

func (p *ProxyHandler) shouldProcessRequest(host string) bool {
	for _, rule := range p.hostRules {
		if strings.Contains(host, rule) {
			return true
		}
	}

	return false
}

func (p *ProxyHandler) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Scheme == "" {
		r.URL.Scheme = "http"
		r.URL.Host = r.Host
	}

	modifyHeader(r)

	resp, err := p.transport.RoundTrip(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)

	plog.Infof("Forwarding request to %s", r.URL.String())
	if _, err := io.Copy(w, resp.Body); err != nil {
		plog.Errorf("Error copying response body: %v", err)
	}
}
