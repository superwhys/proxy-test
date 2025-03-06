package proxy

import (
	"crypto/tls"
	"io"
	"net/http"
	"time"

	"github.com/go-puzzles/puzzles/plog"
	"golang.org/x/sync/errgroup"
)

func (p *ProxyHandler) shouldBlockHTTPS(host string) bool {
	for _, rule := range p.blockHTTPSRules {
		if rule.MatchString(host) {
			plog.Infof("HTTPS domain %s is blocked by rule %s", host, rule.String())
			return true
		}
	}
	return false
}

func (p *ProxyHandler) handleHTTPS(w http.ResponseWriter, r *http.Request) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		plog.Errorf("Failed to send 200 response: %v", err)
		return
	}

	tlsConfig := p.mitmTLSConfig()
	tlsConn := tls.Server(clientConn, tlsConfig)
	defer tlsConn.Close()

	if err := tlsConn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		plog.Errorf("Failed to set deadline: %v", err)
		return
	}

	if err := tlsConn.Handshake(); err != nil {
		plog.Errorf("TLS handshake failed: %v", err)
		return
	}

	targetConn, err := tls.Dial("tcp", r.Host, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		plog.Errorf("Connect to target server failed: %v", err)
		return
	}
	defer targetConn.Close()

	plog.Infof("Forwarding request to %s", r.URL.String())

	wg := &errgroup.Group{}
	wg.Go(func() error {
		_, err := io.Copy(targetConn, tlsConn)
		return err
	})
	wg.Go(func() error {
		_, err := io.Copy(tlsConn, targetConn)
		return err
	})

	if err := wg.Wait(); err != nil {
		plog.Errorf("Copy failed: %v", err)
	}
}
