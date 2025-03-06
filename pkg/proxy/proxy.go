package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/go-puzzles/puzzles/plog"
	"github.com/pkg/errors"
	"github.com/superwhys/haowen/golang/proxy-test/pkg/ca"
)

var (
	blockHTTPSPatterns = []string{
		"github.com",
	}

	hostRules = []string{
		"baidu.com",
		"superwhys.top",
		"httpbin.org",
	}
)

type ProxyHandler struct {
	hostRules       []string
	blockHTTPSRules []*regexp.Regexp
	transport       *http.Transport
	caCert          *x509.Certificate
	caKey           *rsa.PrivateKey
	certCache       map[string]*tls.Certificate
	certCacheMutex  sync.RWMutex
}

func NewProxyHandler() (*ProxyHandler, error) {
	caCert, caKey, err := ca.LoadCA()
	if err != nil {
		return nil, errors.Wrap(err, "load CA failed")
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
		hostRules:       hostRules,
		blockHTTPSRules: blockHTTPSRules,
		transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
		},
		caCert:         caCert,
		caKey:          caKey,
		certCache:      make(map[string]*tls.Certificate),
		certCacheMutex: sync.RWMutex{},
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

	if !p.shouldProcessRequest(host) {
		plog.Infof("Reject request: %s", r.Host)
		http.Error(w, "Access Denied", http.StatusForbidden)
		return
	}

	p.handleHTTP(w, r)
}

func (p *ProxyHandler) createCert(host string) (*tls.Certificate, error) {
	p.certCacheMutex.RLock()
	if cert, ok := p.certCache[host]; ok {
		p.certCacheMutex.RUnlock()
		return cert, nil
	}
	p.certCacheMutex.RUnlock()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, errors.Wrap(err, "generate private key failed")
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, errors.Wrap(err, "generate serial number failed")
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   host,
			Organization: []string{"Proxy CA"},
		},
		NotBefore:             time.Now().Add(-10 * time.Minute),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{host},
	}

	if h, _, err := net.SplitHostPort(host); err == nil {
		template.DNSNames = []string{h}
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		}
	} else {
		if ip := net.ParseIP(host); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, p.caCert, &priv.PublicKey, p.caKey)
	if err != nil {
		return nil, errors.Wrap(err, "create certificate failed")
	}

	cert := &tls.Certificate{
		Certificate: [][]byte{certDER, p.caCert.Raw},
		PrivateKey:  priv,
		Leaf:        template,
	}

	p.certCacheMutex.Lock()
	p.certCache[host] = cert
	p.certCacheMutex.Unlock()

	return cert, nil
}

func (p *ProxyHandler) mitmTLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			host := info.ServerName
			if host == "" {
				host = "unknown"
			}
			return p.createCert(host)
		},
	}
}
