package proxy

import "net/http"

func modifyHeader(r *http.Request) {
	r.Header.Set("X-Proxy-Modified", "true")
	r.Header.Set("X-Custom-Header", "modified-by-proxy")
}
