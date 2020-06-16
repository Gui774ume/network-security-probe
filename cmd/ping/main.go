/*
Copyright © 2020 GUILLAUME FOURNIER

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package main

import (
	"flag"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
	muxtrace "gopkg.in/DataDog/dd-trace-go.v1/contrib/gorilla/mux"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"
)

var (
	pingLogger = logrus.WithField("service", "ping")
)

func main() {
	// Parse parameters
	bind := flag.String("bind", "0.0.0.0:80", "Bind address for the ping server")
	agent := flag.String("agent", "localhost:8126", "Datadog agent URL")
	pong := flag.String("pong", "", "Pong server URL")
	flag.Parse()
	// Set log formatter
	logrus.SetFormatter(&logrus.JSONFormatter{})
	tracer.Start(
		tracer.WithAgentAddr(
			*agent,
		),
	)
	// Initializes mux tracer
	muxtracer := muxtrace.NewRouter(
		muxtrace.WithServiceName("ping"),
	)
	muxtracer.HandleFunc("/version", versionHandler)
	// Start ping background task
	if *pong != "" {
		go pingSender(*pong)
	}
	// Start Ping server
	pingLogger.Infof("Ping server started on: %v", *bind)
	pingLogger.Fatal(http.ListenAndServe(*bind, muxtracer))
}

func versionHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Ping server v1.0\n"))
}

func pingSender(pong string) {
	for {
		tr := &http.Transport{
			MaxIdleConns:    10,
			IdleConnTimeout: 30 * time.Second,
		}
		client := &http.Client{
			Transport: tr,
			Timeout:   25 * time.Second,
		}
		resp, err := client.Get(pong)
		if err != nil {
			pingLogger.Errorf("Couldn't send ping request: %v", err)
		} else {
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				pingLogger.Errorf("Couldn't read response: %v", err)
			}
			pingLogger.Infof("Received: %v", string(body))
			resp.Body.Close()
		}
		time.Sleep(1 * time.Second)
	}
}
