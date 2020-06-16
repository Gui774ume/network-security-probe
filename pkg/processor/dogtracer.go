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
package processor

import (
	"encoding/json"
	"fmt"
	"net"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/Gui774ume/network-security-probe/pkg/model"
)

var (
	dogLogger = logrus.WithField("package", "processor")
)

// DogTracer - Datadog forwarder processor
type DogTracer struct {
	wg        *sync.WaitGroup
	stop      chan struct{}
	EventChan chan model.ProbeEvent
	conn      net.Conn
}

// GetName - Returns the processor name
func (dt *DogTracer) GetName() model.ProcessorName {
	return model.DogTracerProcessor
}

// GetEventChan - Returns event channel
func (dt *DogTracer) GetEventChan() chan model.ProbeEvent {
	return dt.EventChan
}

// Start - Starts tracer
func (dt *DogTracer) Start(nsp model.NSPInterface) error {
	dt.wg = nsp.GetWaitGroup()
	dt.EventChan = make(chan model.ProbeEvent, nsp.GetConfig().EBPF.MapsChannelLength)
	dt.stop = make(chan struct{})
	agentURL := nsp.GetConfig().CLI.DDLogURL
	if agentURL == "" {
		return nil
	}
	// Prepare connection with the agent
	var err error
	dt.conn, err = net.Dial("udp", agentURL)
	if err != nil {
		return fmt.Errorf("couldn't connect to the agent: %v", err)
	}
	go dt.listen()
	return nil
}

// listen - Wait for events and print them
func (dt *DogTracer) listen() {
	dt.wg.Add(1)
	var event model.ProbeEvent
	var ok bool
	for {
		select {
		case <-dt.stop:
			dt.wg.Done()
			return
		case event, ok = <-dt.EventChan:
			if !ok {
				dt.wg.Done()
				return
			}
			// Send to Datadog
			data, err := json.Marshal(event)
			if err != nil {
				dogLogger.Errorf("couldn't marshal event type: %v\n", event.GetEventType())
				continue
			}
			if _, err := dt.conn.Write(data); err != nil {
				dogLogger.Errorf("couldn't send event to the agent: %v", err)
			}
		}
	}
}

// Stop - Stop tracer
func (dt *DogTracer) Stop() error {
	close(dt.stop)
	close(dt.EventChan)
	return nil
}
