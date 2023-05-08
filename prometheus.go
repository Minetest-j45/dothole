package main

import (
	"log"
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

func startPrometheus(stats map[string]prometheus.Counter) {
    stats["total_queries"] = promauto.NewCounter(prometheus.CounterOpts{
        Name: "total_queries",
        Help: "Total number of queries processed since last restart",
    })

    http.Handle("/metrics", promhttp.Handler())
    err := http.ListenAndServeTLS(":8080", "cert.pem", "key.pem", nil)
    if err != nil {
        log.Println("Error while starting prometheus https server", err)
    }
}
