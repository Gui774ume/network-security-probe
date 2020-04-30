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
