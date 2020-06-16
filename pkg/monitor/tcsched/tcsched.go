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
package tcsched

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/Gui774ume/ebpf"
	"github.com/florianl/go-tc"
	"github.com/sirupsen/logrus"

	"github.com/Gui774ume/network-security-probe/pkg/model"
	"github.com/Gui774ume/network-security-probe/pkg/model/kernel"
	"github.com/Gui774ume/network-security-probe/pkg/monitor/base"
	"github.com/Gui774ume/network-security-probe/pkg/utils"
)

var (
	netLogger = logrus.WithField("package", "netdevice")
)

// Monitor - Dummy monitor to catch network alerts
var Monitor = base.Monitor{
	Name: model.NetworkAlertMonitor,
	Probes: []*base.Probe{
		&base.Probe{
			Name:    "NetworkAlert",
			Enabled: true,
			PerfMaps: []*base.PerfMap{
				&base.PerfMap{
					PerfOutputMapName: "net_alerts",
					DataHandler:       traceNetAlerts,
				},
				&base.PerfMap{
					PerfOutputMapName: "dns_queries",
					DataHandler:       traceDNSQueries,
				},
				&base.PerfMap{
					PerfOutputMapName: "dns_responses",
					DataHandler:       traceDNSResponses,
				},
			},
		},
	},
}

// traceNetAlerts - Traces network alerts
func traceNetAlerts(data []byte, m *base.Monitor) {
	var eventRaw model.NetworkAlertRaw
	if err := binary.Read(bytes.NewBuffer(data), utils.GetHostByteOrder(), &eventRaw); err != nil {
		netLogger.Errorf("failed to decode received data (DeviceEventRaw): %s\n", err)
		return
	}
	// Prepare event
	event := model.NetworkAlertEvent{
		EventBase: model.EventBase{
			EventMonitorName: m.Name,
			EventType:        model.NetworkAlertType,
			Timestamp:        m.Nsp.GetBootTime().Add(time.Duration(eventRaw.TimestampRaw) * time.Nanosecond),
		},
		NetworkAlertRaw: &eventRaw,
		SourceMACAddr:   utils.Char6ToEth(eventRaw.SourceMACAddrRaw),
		DestMACAddr:     utils.Char6ToEth(eventRaw.DestMACAddrRaw),
	}

	switch event.NProtocol {
	case kernel.EthPIP:
		event.SourceIP = utils.Uint64ToIPv4(eventRaw.SourceIPRaw[0])
		event.DestIP = utils.Uint64ToIPv4(eventRaw.DestIPRaw[0])
	case kernel.EthPIPV6:
		event.SourceIP = utils.Uint64sToIPv6(eventRaw.SourceIPRaw)
		event.DestIP = utils.Uint64sToIPv6(eventRaw.DestIPRaw)
	}

	// Dispatch event
	m.Nsp.DispatchEvent(&event)
}

// traceDNSQueries - Traces DNS queries
func traceDNSQueries(data []byte, m *base.Monitor) {
	var eventRaw model.DNSQueryRaw
	if err := binary.Read(bytes.NewBuffer(data), utils.GetHostByteOrder(), &eventRaw); err != nil {
		netLogger.Errorf("failed to decode received data (DeviceEventRaw): %s\n", err)
		return
	}
	// Prepare event
	event := model.DNSQueryEvent{
		EventBase: model.EventBase{
			EventMonitorName: m.Name,
			EventType:        model.DNSQueryType,
			Timestamp:        m.Nsp.GetBootTime().Add(time.Duration(eventRaw.TimestampRaw) * time.Nanosecond),
		},
		DNSQueryRaw:   &eventRaw,
		SourceMACAddr: utils.Char6ToEth(eventRaw.SourceMACAddrRaw),
		DestMACAddr:   utils.Char6ToEth(eventRaw.DestMACAddrRaw),
		Domain:        utils.DecodeDNS(eventRaw.DNSQuerySpec.DNSKey.NameRaw),
	}

	switch event.NProtocol {
	case kernel.EthPIP:
		event.SourceIP = utils.Uint64ToIPv4(eventRaw.SourceIPRaw[0])
		event.DestIP = utils.Uint64ToIPv4(eventRaw.DestIPRaw[0])
	case kernel.EthPIPV6:
		event.SourceIP = utils.Uint64sToIPv6(eventRaw.SourceIPRaw)
		event.DestIP = utils.Uint64sToIPv6(eventRaw.DestIPRaw)
	}

	// Dispatch event
	m.Nsp.DispatchEvent(&event)
}

// traceDNSResponses - Traces DNS responses
func traceDNSResponses(data []byte, m *base.Monitor) {
	var eventRaw model.DNSResponseRaw
	if err := binary.Read(bytes.NewBuffer(data), utils.GetHostByteOrder(), &eventRaw); err != nil {
		netLogger.Errorf("failed to decode received data (DeviceEventRaw): %s\n", err)
		return
	}
	// Prepare event
	event := model.DNSResponseEvent{
		EventBase: model.EventBase{
			EventMonitorName: m.Name,
			EventType:        model.DNSResponseType,
			Timestamp:        m.Nsp.GetBootTime().Add(time.Duration(eventRaw.TimestampRaw) * time.Nanosecond),
		},
		DNSResponseRaw: &eventRaw,
		SourceMACAddr:  utils.Char6ToEth(eventRaw.SourceMACAddrRaw),
		DestMACAddr:    utils.Char6ToEth(eventRaw.DestMACAddrRaw),
		Domain:         utils.DecodeDNS(eventRaw.DNSResponseSpec.DNSKey.NameRaw),
		QueryTimestamp: m.Nsp.GetBootTime().Add(time.Duration(eventRaw.QueryTimestampRaw) * time.Nanosecond),
	}
	event.ResponseTime = event.Timestamp.Sub(event.QueryTimestamp)

	switch event.NProtocol {
	case kernel.EthPIP:
		event.SourceIP = utils.Uint64ToIPv4(eventRaw.SourceIPRaw[0])
		event.DestIP = utils.Uint64ToIPv4(eventRaw.DestIPRaw[0])
	case kernel.EthPIPV6:
		event.SourceIP = utils.Uint64sToIPv6(eventRaw.SourceIPRaw)
		event.DestIP = utils.Uint64sToIPv6(eventRaw.DestIPRaw)
	}

	switch event.DNSResponseSpec.Type {
	case kernel.ARecord:
		event.ResolvedIP = utils.Uint64ToIPv4(eventRaw.DNSResponseSpec.IPRaw[0])
	case kernel.AAAARecord:
		event.ResolvedIP = utils.Uint64sToIPv6(eventRaw.DNSResponseSpec.IPRaw)
	}

	// Dispatch event
	m.Nsp.DispatchEvent(&event)
}

// NewTCMonitor - Returns a new TC monitor for the provided network device
func NewTCMonitor(event *model.DeviceEvent) *base.Monitor {
	monitor := base.Monitor{
		Name:    model.MonitorName(fmt.Sprintf("TCMonitor_%s", event.DeviceName)),
		Ifindex: event.Device.Ifindex,
	}
	// Set up classic ingress and egress classifiers for veth pair
	if event.Device.PeerIfindex != 0 {
		// For a veth pair device, Egress and Ingress are inverted from what you
		// would expect.
		monitor.Probes = []*base.Probe{
			&base.Probe{
				Name:        fmt.Sprintf("SchedIngress_%s", event.DeviceName),
				Enabled:     true,
				Type:        ebpf.SchedCLS,
				SectionName: "classifier/ingress_cls",
				QdiscParent: tc.Egress,
				PerfMaps:    []*base.PerfMap{},
			},
			&base.Probe{
				Name:        fmt.Sprintf("SchedEgress_%s", event.DeviceName),
				Enabled:     true,
				Type:        ebpf.SchedCLS,
				SectionName: "classifier/egress_cls",
				QdiscParent: tc.Ingress,
				PerfMaps:    []*base.PerfMap{},
			},
		}
	} else {
		monitor.Probes = []*base.Probe{
			&base.Probe{
				Name:        fmt.Sprintf("SchedExtIngress_%s", event.DeviceName),
				Enabled:     true,
				Type:        ebpf.SchedCLS,
				SectionName: "classifier/ingress_ext_cls",
				QdiscParent: tc.Ingress,
				PerfMaps:    []*base.PerfMap{},
			},
			&base.Probe{
				Name:        fmt.Sprintf("SchedExtEgress_%s", event.DeviceName),
				Enabled:     true,
				Type:        ebpf.SchedCLS,
				SectionName: "classifier/egress_ext_cls",
				QdiscParent: tc.Egress,
				PerfMaps:    []*base.PerfMap{},
			},
		}
	}
	return &monitor
}
