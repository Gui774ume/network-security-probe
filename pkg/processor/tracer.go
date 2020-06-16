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
	"sync"

	"github.com/Gui774ume/network-security-probe/pkg/model"
)

// Tracer - Tracer struct
type Tracer struct {
	wg        *sync.WaitGroup
	stop      chan struct{}
	EventChan chan model.ProbeEvent
}

// GetName - Returns the processor name
func (t *Tracer) GetName() model.ProcessorName {
	return model.TracerProcessor
}

// GetEventChan - Returns event channel
func (t *Tracer) GetEventChan() chan model.ProbeEvent {
	return t.EventChan
}

// Start - Starts tracer
func (t *Tracer) Start(nsp model.NSPInterface) error {
	t.wg = nsp.GetWaitGroup()
	t.EventChan = make(chan model.ProbeEvent, nsp.GetConfig().EBPF.MapsChannelLength)
	t.stop = make(chan struct{})
	go t.listen()
	return nil
}

// listen - Wait for events and print them
func (t *Tracer) listen() {
	t.wg.Add(1)
	var event model.ProbeEvent
	var ok bool
	for {
		select {
		case <-t.stop:
			t.wg.Done()
			return
		case event, ok = <-t.EventChan:
			if !ok {
				t.wg.Done()
				return
			}
			entry := event.GetLogEntry()
			ns := event.GetNamespaceCacheData()
			if ns != nil {
				entry = entry.WithField("namespace", ns.Name)
			}
			ps := event.GetProcessCacheData()
			if ps != nil {
				entry = entry.WithField("process", ps.BinaryPath)
			}
			entry.Info(event.GetMessage())
		}
	}
}

// Stop - Stop tracer
func (t *Tracer) Stop() error {
	close(t.stop)
	close(t.EventChan)
	return nil
}
