package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	muxtrace "gopkg.in/DataDog/dd-trace-go.v1/contrib/gorilla/mux"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"
)

var (
	pongLogger = logrus.WithField("service", "pong")
)

func main() {
	// Parse parameters
	bind := flag.String("bind", "0.0.0.0:80", "Bind address for the pong server")
	agent := flag.String("agent", "localhost:8126", "Datadog agent URL")
	ping := flag.String("ping", "", "Ping server URL")
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
		muxtrace.WithServiceName("pong"),
	)
	muxtracer.HandleFunc("/task", pingHandler)
	// Ping version goroutine
	if *ping != "" {
		go pingVersion(*ping)
	}
	// Start Pong server
	pongLogger.Infof("Pong server started on: %v\n", *bind)
	log.Fatal(http.ListenAndServe(*bind, muxtracer))
}

func pingHandler(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Request failed"))
		return
	}
	output, _ := complexProcessing(r.Context(), string(body))
	w.Write([]byte(fmt.Sprintf("pong!\n%v\n", output)))
}

func complexProcessing(ctx context.Context, body string) (string, error) {
	span, ctx := tracer.StartSpanFromContext(ctx, "task.processing")
	defer span.Finish()
	if body == "" {
		body = "date"
	}
	tasks := strings.Split(body, " ")
	output, err := computeTasks(tasks, span)
	if err != nil {
		return "", err
	}
	return output, nil
}

func computeTasks(tasks []string, span tracer.Span) (string, error) {
	child := tracer.StartSpan("task.scheduling", tracer.ChildOf(span.Context()))
	defer child.Finish()
	pongLogger.Infof("Executing tasks: %v\n", tasks)
	output, err := execTask(tasks, child)
	if err == nil {
		pongLogger.Infof("done: %v", output)
	} else {
		pongLogger.Errorf("error: %v\n", err)
	}
	return output, err
}

func execTask(command []string, span tracer.Span) (string, error) {
	child := tracer.StartSpan("task.exec", tracer.ChildOf(span.Context()))
	out, err := exec.Command(command[0], command[1:]...).Output()
	child.Finish(tracer.WithError(err))
	return string(out), err
}

func pingVersion(ping string) {
	for {
		tr := &http.Transport{
			MaxIdleConns:    10,
			IdleConnTimeout: 30 * time.Second,
		}
		client := &http.Client{
			Transport: tr,
			Timeout:   25 * time.Second,
		}
		resp, err := client.Get(ping)
		if err != nil {
			pongLogger.Errorf("Couldn't get ping version: %v", err)
		} else {
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				pongLogger.Errorf("Couldn't read ping version response: %v", err)
			}
			pongLogger.Infof("Ping Version: %v", string(body))
		}
		time.Sleep(1 * time.Second)
	}
}
