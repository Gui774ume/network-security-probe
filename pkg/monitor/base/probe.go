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
package base

import (
	"fmt"
	"os"
	"sync"

	"github.com/Gui774ume/ebpf"
	"github.com/florianl/go-tc"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/Gui774ume/network-security-probe/pkg/config"
	"github.com/Gui774ume/network-security-probe/pkg/model"
)

var (
	baseLogger = logrus.WithField("package", "base")
)

// SnapshotFunc - Snapshot function for the given monitor
type SnapshotFunc func(m *Monitor) error

// Monitor - Base monitor
type Monitor struct {
	Name         model.MonitorName
	SnapshotFunc SnapshotFunc
	Nsp          model.NSPInterface
	wg           *sync.WaitGroup
	config       *config.NSPConfig
	collection   *ebpf.Collection
	// eBPF specific fields
	MapNames []string
	Probes   []*Probe
	// SchedCLS specific parameters
	Ifindex   int32
	Netns     int
	rtNetlink *tc.Tc
	qdisc     *tc.Object
}

// GetName - Returns the monitor name
func (m *Monitor) GetName() model.MonitorName {
	return m.Name
}

// enabledProbeCount - Returns the number of enabled probes
func (m *Monitor) enabledProbeCount() int {
	count := 0
	for _, m := range m.Probes {
		if m.Enabled {
			count = count + 1
		}
	}
	return count
}

// Init - Initializes the monitor
func (m *Monitor) Init(nsp model.NSPInterface) error {
	m.Nsp = nsp
	m.wg = nsp.GetWaitGroup()
	m.config = nsp.GetConfig()
	m.collection = nsp.GetCollection()
	// Create RTNetLink connection and create Qdisc if
	// the monitor requires it
	if m.Ifindex != 0 {
		if err := m.setupRTNetLink(); err != nil {
			return err
		}
		if err := m.createQdisc(); err != nil {
			return err
		}
	}
	// Init probes
	for _, p := range m.Probes {
		if err := p.Init(m); err != nil {
			return err
		}
	}
	return nil
}

// setupRTNetLink - Sets up a connection with RTNetlink
func (m *Monitor) setupRTNetLink() error {
	var err error
	m.rtNetlink, err = tc.Open(&tc.Config{
		NetNS: m.Netns,
	})
	return err
}

// createQdisc - Sets up a qdisc on the provided interface
func (m *Monitor) createQdisc() error {
	// Create a Qdisc for the provided interface
	m.qdisc = &tc.Object{
		tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(m.Ifindex),
			Handle:  tc.BuildHandle(0xFFFF, 0x0000),
			Parent:  0xFFFFFFF1,
			Info:    0,
		},
		tc.Attribute{
			Kind: "clsact",
		},
	}
	// Add the Qdisc
	if err := m.rtNetlink.Qdisc().Add(m.qdisc); err != nil {
		baseLogger.Errorf("couldn't add a \"clsact\" qdisc to interface %v: %v", m.Ifindex, err)
		return err
	}
	return nil
}

// Start - Starts the monitor
func (m *Monitor) Start() error {
	// start probes
	for _, p := range m.Probes {
		if err := p.Start(); err != nil {
			baseLogger.Errorf("couldn't start probe \"%s\": %v", p.Name, err)
			return err
		}
	}
	if m.SnapshotFunc != nil {
		if err := m.SnapshotFunc(m); err != nil {
			baseLogger.Errorf(
				"coudln't execute snapshot function \"%s\": %v",
				m.Name,
				err,
			)
		}
	}
	baseLogger.Debugf("%s monitor has %d probe(s) running", m.GetName(), m.enabledProbeCount())
	return nil
}

// Stop - Stops the monitor
func (m *Monitor) Stop() error {
	// Stop probes
	for _, p := range m.Probes {
		if err := p.Stop(); err != nil {
			baseLogger.Errorf("couldn't stop probe \"%s\": %v", p.Name, err)
		}
	}
	// Remove qdisc
	if m.Ifindex == 0 {
		return nil
	}
	var errTmp, err error
	// Delete qdisc (it will also delete any filter associated to this qdisc)
	if errTmp = m.rtNetlink.Qdisc().Delete(m.qdisc); err != nil {
		err = fmt.Errorf("coudln't delete \"clsact\" qdisc from interface %v: %v", m.Ifindex, errTmp)
	}
	// Close RTNetlink connection
	if errTmp = m.rtNetlink.Close(); err != nil {
		if err == nil {
			err = fmt.Errorf("couldn't close RTNetlink connection: %v", errTmp)
		} else {
			errTmp = fmt.Errorf("couldn't close RTNetlink connection: %v", errTmp)
			err = fmt.Errorf("%v, %v", err, errTmp)
		}
	}
	return err
}

// Probe - eBPF probe structure
type Probe struct {
	Name        string
	Enabled     bool
	monitor     *Monitor
	Type        ebpf.ProgType
	SectionName string
	// Kprobe specific parameters
	KProbeMaxActive int
	// UProbe specific parameters
	UProbeFilename string
	UProbeOffset   uint64
	// SchedCLS specific parameters
	QdiscParent uint32
	schedCLSFd  int
	// Cgroup specific parameters
	CgroupPath string
	// Perf maps
	PerfMaps []*PerfMap
}

// Init - Initializes the probe
func (p *Probe) Init(m *Monitor) error {
	p.monitor = m
	// Prepare perf maps
	for _, m := range p.PerfMaps {
		if err := m.init(p); err != nil {
			return err
		}
	}
	return nil
}

// Start - Starts the probe
func (p *Probe) Start() error {
	if !p.Enabled {
		return nil
	}
	// Enable eBPF program
	collection := p.monitor.collection
	switch p.Type {
	case ebpf.TracePoint:
		if err := collection.EnableTracepoint(p.SectionName); err != nil {
			return err
		}
	case ebpf.Kprobe:
		maxActive := p.monitor.config.EBPF.KprobeMaxActive
		if p.KProbeMaxActive != 0 {
			maxActive = p.KProbeMaxActive
		}
		if err := collection.EnableKprobe(p.SectionName, maxActive); err != nil {
			return err
		}
	case ebpf.SchedCLS:
		sp := collection.Programs[p.SectionName]
		if sp == nil {
			return errors.New("SchedCLS program not found")
		}
		p.schedCLSFd = sp.FD()
		if err := p.addFilter(); err != nil {
			return err
		}
	case ebpf.CGroupSock, ebpf.CGroupSKB, ebpf.SockOps, ebpf.CGroupDevice:
		if err := collection.AttachCgroupProgram(p.SectionName, p.CgroupPath); err != nil {
			return err
		}
	}
	// start polling perf maps
	for _, m := range p.PerfMaps {
		if err := m.pollStart(); err != nil {
			return err
		}
	}
	return nil
}

// addFilter - Adds a filter on the provided interface
func (p *Probe) addFilter() error {
	// Add qdisc filter
	filter := tc.Object{
		tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(p.monitor.Ifindex),
			Handle:  0,
			Parent:  p.QdiscParent,
			Info:    0x300,
		},
		tc.Attribute{
			Kind: "bpf",

			BPF: &tc.Bpf{
				FD:    uint32(p.schedCLSFd),
				Name:  p.SectionName,
				Flags: 0x1,
			},
		},
	}
	if err := p.monitor.rtNetlink.Filter().Add(&filter); err != nil {
		baseLogger.Errorf("couldn't add a %v filter to interface %v: %v", p.QdiscParent, p.monitor.Ifindex, err)
		return err
	}
	return nil
}

// Stop - Stops the probe
func (p *Probe) Stop() error {
	if !p.Enabled {
		return nil
	}
	// stop polling perf maps
	for _, m := range p.PerfMaps {
		if err := m.pollStop(); err != nil {
			baseLogger.Errorf("couldn't close perf map %v gracefully: %v", m.PerfOutputMapName, err)
		}
	}
	return nil
}

// lostMetrics - Reacts on lost metrics
func lostMetrics(count uint64, mapName string, m *Monitor) {
	baseLogger.Warnf("%v lost %v events", mapName, count)
}

// PerfMap - Definition of a perf map, used to bring data back to user space
type PerfMap struct {
	probe              *Probe
	perfReader         *ebpf.PerfReader
	perfMap            *ebpf.Map
	UserSpaceBufferLen int
	PerfOutputMapName  string
	event              chan []byte
	lost               chan uint64
	stop               chan struct{}
	DataHandler        func(data []byte, m *Monitor)
	LostHandler        func(count uint64, mapName string, m *Monitor)
}

// init - Initializes perfmap
func (m *PerfMap) init(p *Probe) error {
	m.probe = p
	if m.DataHandler == nil {
		return errors.New("Data handler not set")
	}
	if m.LostHandler == nil {
		m.LostHandler = lostMetrics
	}
	// Default userspace buffer length
	if m.UserSpaceBufferLen == 0 {
		m.UserSpaceBufferLen = m.probe.monitor.config.EBPF.MapsChannelLength
	}
	// Select map
	var ok bool
	m.perfMap, ok = p.monitor.collection.Maps[m.PerfOutputMapName]
	if !ok {
		errors.Wrapf(
			errors.New("map not found"),
			"couldn't init map %s",
			m.PerfOutputMapName,
		)
	}
	// Init channels
	m.stop = make(chan struct{})
	return nil
}

func (m *PerfMap) pollStart() error {
	pageSize := os.Getpagesize()
	// Start perf map
	var err error
	m.perfReader, err = ebpf.NewPerfReader(ebpf.PerfReaderOptions{
		Map:               m.perfMap,
		PerCPUBuffer:      m.probe.monitor.config.EBPF.PerfMapPageCount * pageSize,
		Watermark:         1,
		UserSpaceChanSize: m.UserSpaceBufferLen,
	})
	if err != nil {
		return errors.Wrapf(err, "couldn't start map %s", m.PerfOutputMapName)
	}
	go m.listen()
	return nil
}

// listen - Listen for new events from the kernel
func (m *PerfMap) listen() {
	m.probe.monitor.wg.Add(1)
	var sample *ebpf.PerfSample
	var ok bool
	var lostCount uint64
	for {
		select {
		case <-m.stop:
			m.probe.monitor.wg.Done()
			return
		case sample, ok = <-m.perfReader.Samples:
			if !ok {
				m.probe.monitor.wg.Done()
				return
			}
			m.DataHandler(sample.Data, m.probe.monitor)
		case lostCount, ok = <-m.perfReader.LostRecords:
			if !ok {
				m.probe.monitor.wg.Done()
				return
			}
			if m.LostHandler != nil {
				m.LostHandler(lostCount, m.PerfOutputMapName, m.probe.monitor)
			}
		}
	}
}

// pollStop - Stop a perf map listener
func (m *PerfMap) pollStop() error {
	err := m.perfReader.FlushAndClose()
	close(m.stop)
	return err
}
