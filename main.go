package main

import (
	"net/http"

	"github.com/go-puzzles/puzzles/plog"
	"github.com/superwhys/haowen/golang/proxy-test/pkg/proxy"
)

const (
	port = ":8080"
)

func main() {
	proxy, err := proxy.NewProxyHandler()
	plog.PanicError(err)

	server := &http.Server{
		Addr:    port,
		Handler: proxy,
	}

	plog.Infof("Server started at %s", port)
	plog.PanicError(server.ListenAndServe())
}
