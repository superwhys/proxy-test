package proxy

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/go-puzzles/puzzles/plog"
	"github.com/pkg/errors"
	"github.com/superwhys/haowen/golang/proxy-test/pkg/ca"
)

type ProxyHandler struct {
	forwardRules    []string
	modifyRules     []string
	blockHTTPSRules []*regexp.Regexp
	transport       *http.Transport
	caCert          *x509.Certificate
	caKey           *rsa.PrivateKey
	certCache       sync.Map
}

func NewProxyHandler(caCert *x509.Certificate, caKey *rsa.PrivateKey) (*ProxyHandler, error) {

	blockHTTPSPatterns := []string{
		`^example\.com$`,
		`.*\.example\.com$`,
		`^(.*\.)?example\.[^.]+$`,
	}

	blockHTTPSRules := make([]*regexp.Regexp, 0, len(blockHTTPSPatterns))
	for _, pattern := range blockHTTPSPatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, errors.Wrapf(err, "Compile block HTTPS pattern %s", pattern)
		}
		blockHTTPSRules = append(blockHTTPSRules, re)
	}

	return &ProxyHandler{
		forwardRules:    []string{"superwhys.com"},
		modifyRules:     []string{"superwhys.top"},
		blockHTTPSRules: blockHTTPSRules,
		transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
		},
		caCert: caCert,
		caKey:  caKey,
	}, nil
}

func (p *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		if p.shouldBlockHTTPS(r.Host) {
			plog.Infof("Reject HTTPS request: %s", r.Host)
			http.Error(w, "HTTPS Access Denied", http.StatusForbidden)
			return
		}
		p.handleHTTPS(w, r)
		return
	}

	host := r.Host

	if p.shouldModifyHeaders(host) {
		r.Header.Set("X-Proxy-Modified", "true")
		r.Header.Set("X-Custom-Header", "modified-by-proxy")
	}

	if p.shouldForward(host) {
		p.forwardRequest(w, r)
		return
	}

	p.forwardRequest(w, r)
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

	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	cert, err := p.getCertificate(r.Host)
	if err != nil {
		plog.Errorf("Get certificate failed: %v", err)
		clientConn.Close()
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
	}
	tlsConn := tls.Server(clientConn, tlsConfig)
	defer tlsConn.Close()

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

	go io.Copy(targetConn, tlsConn)
	io.Copy(tlsConn, targetConn)
}

func (p *ProxyHandler) getCertificate(host string) (*tls.Certificate, error) {
	if cert, ok := p.certCache.Load(host); ok {
		return cert.(*tls.Certificate), nil
	}

	cert, err := ca.GenerateCert(host, p.caCert, p.caKey)
	if err != nil {
		return nil, err
	}

	p.certCache.Store(host, cert)
	return cert, nil
}

func (p *ProxyHandler) shouldModifyHeaders(host string) bool {
	for _, rule := range p.modifyRules {
		if strings.Contains(host, rule) {
			return true
		}
	}
	return false
}

func (p *ProxyHandler) shouldForward(host string) bool {
	for _, rule := range p.forwardRules {
		if strings.Contains(host, rule) {
			return true
		}
	}
	return false
}

func (p *ProxyHandler) shouldBlockHTTPS(host string) bool {
	for _, rule := range p.blockHTTPSRules {
		if rule.MatchString(host) {
			plog.Infof("HTTPS domain %s is blocked by rule %s", host, rule.String())
			return true
		}
	}
	return false
}

func (p *ProxyHandler) forwardRequest(w http.ResponseWriter, r *http.Request) {
	if r.URL.Scheme == "" {
		r.URL.Scheme = "http"
		r.URL.Host = r.Host
	}

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
