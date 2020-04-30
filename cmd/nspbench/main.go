package main

import (
	"crypto/tls"
	"log"
	"net/http"
	"net/http/httptrace"
	"time"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

var (
	domains = []string{
		"pong.default.svc.cluster.local",
		"google.fr",
		"google.com",
		"facebook.com",
		"github.com",
		"cloudflare.com",
	}
	n       = int64(1000)
	server  = "10.96.0.10"
	logger  = logrus.WithField("package", "nspbench")
	pongURL = "http://pong.default.svc.cluster.local/task"
)

func resolveDomain(domain string) time.Duration {
	c := dns.Client{}
	m := dns.Msg{}
	m.SetQuestion(domain+".", dns.TypeA)
	_, t, err := c.Exchange(&m, server+":53")
	if err != nil {
		log.Fatal(err)
	}
	return t
}

func main() {
	// Compute DNS latency
	logger.Infof("Starting DNS benchmark (avg rtt over %v) ...\n", n)
	for _, domain := range domains {
		sum := 0 * time.Second
		for i := int64(0); i < n; i++ {
			sum += resolveDomain(domain)
		}
		logger.Infof("%v: %v\n", domain, time.Duration(sum.Nanoseconds()/n))
	}
	// Compute normal traffic latency
	sum := 0 * time.Second
	for i := int64(0); i < 5*n; i++ {
		sum += mesureGet(pongURL)
	}
	logger.Infof("Average packet round trip time (pong task): %v\n", time.Duration(sum.Nanoseconds()/(5*n)))
}

func mesureGet(url string) time.Duration {
	req, _ := http.NewRequest("GET", url, nil)

	var start, connectStart, dnsStart, tlsHandshakeStart time.Time
	var connectDuration, dnsDuration, tlsDuration, firstByte time.Duration

	trace := &httptrace.ClientTrace{
		DNSStart: func(dsi httptrace.DNSStartInfo) { dnsStart = time.Now() },
		DNSDone: func(ddi httptrace.DNSDoneInfo) {
			dnsDuration = time.Since(dnsStart)
		},

		TLSHandshakeStart: func() { tlsHandshakeStart = time.Now() },
		TLSHandshakeDone: func(cs tls.ConnectionState, err error) {
			tlsDuration = time.Since(tlsHandshakeStart)
		},

		ConnectStart: func(network, addr string) { connectStart = time.Now() },
		ConnectDone: func(network, addr string, err error) {
			connectDuration = time.Since(connectStart)
		},

		GotFirstResponseByte: func() {
			firstByte = time.Since(start)
		},
	}

	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	start = time.Now()
	if _, err := http.DefaultTransport.RoundTrip(req); err != nil {
		log.Fatal(err)
	}
	return firstByte - connectDuration - tlsDuration - dnsDuration
}
