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
package netdevice

import (
	"C"
	"bytes"
	"encoding/binary"
	"time"
	"unsafe"

	"github.com/Gui774ume/ebpf"
	"github.com/sirupsen/logrus"

	"github.com/Gui774ume/network-security-probe/pkg/model"
	"github.com/Gui774ume/network-security-probe/pkg/monitor/base"
	"github.com/Gui774ume/network-security-probe/pkg/utils"
)

var (
	netLogger = logrus.WithField("package", "netdevice")
)

// Monitor - Network device monitor
var Monitor = base.Monitor{
	Name: model.NetDeviceMonitor,
	Probes: []*base.Probe{
		&base.Probe{
			Name:        "DeviceChangeNetNamespace",
			Enabled:     true,
			Type:        ebpf.Kprobe,
			SectionName: "kprobe/dev_change_net_namespace",
			PerfMaps: []*base.PerfMap{
				&base.PerfMap{
					PerfOutputMapName: "device_netns_update",
					DataHandler:       traceDeviceNetnsUpdate,
				},
			},
		},
		&base.Probe{
			Name:        "FreeNetDevice",
			Enabled:     false,
			Type:        ebpf.Kprobe,
			SectionName: "kprobe/free_netdev",
		},
		&base.Probe{
			Name:        "UnregisterNetDevice",
			Enabled:     true,
			Type:        ebpf.Kprobe,
			SectionName: "kprobe/unregister_netdevice_queue",
		},
		&base.Probe{
			Name:        "VethNewLink",
			Enabled:     true,
			Type:        ebpf.Kprobe,
			SectionName: "kprobe/veth_newlink",
		},
		&base.Probe{
			Name:        "RegisterNetDevice",
			Enabled:     true,
			Type:        ebpf.Kprobe,
			SectionName: "kprobe/register_netdevice",
		},
		&base.Probe{
			Name:        "RegisterNetDeviceRet",
			Enabled:     true,
			Type:        ebpf.Kprobe,
			SectionName: "kretprobe/register_netdevice",
			PerfMaps: []*base.PerfMap{
				&base.PerfMap{
					PerfOutputMapName: "device_events",
					DataHandler:       traceNewNetDevice,
				},
			},
		},
	},
}

// traceNewNetDevice - Traces new network device registration
func traceNewNetDevice(data []byte, m *base.Monitor) {
	var eventRaw model.DeviceEventRaw
	if err := binary.Read(bytes.NewBuffer(data), utils.GetHostByteOrder(), &eventRaw); err != nil {
		netLogger.Errorf("failed to decode received data (DeviceEventRaw): %s\n", err)
		return
	}
	// Prepare event
	event := model.DeviceEvent{
		EventBase: model.EventBase{
			EventMonitorName: m.Name,
			EventType:        model.NewNetDeviceType,
			Timestamp:        m.Nsp.GetBootTime().Add(time.Duration(eventRaw.Metadata.TimestampRaw) * time.Nanosecond),
			TTYName:          C.GoString((*C.char)(unsafe.Pointer(&eventRaw.Metadata.TTYNameRaw))),
		},
		DeviceEventRaw: &eventRaw,
		DeviceName:     C.GoString((*C.char)(unsafe.Pointer(&eventRaw.Device.NameRaw))),
		PeerName:       C.GoString((*C.char)(unsafe.Pointer(&eventRaw.Peer.NameRaw))),
	}
	switch event.EventFlag {
	case model.DeviceRegistration:
		// Create a new Classifier for the new interface.
		m.Nsp.SetupDeviceMonitor(&event)
	case model.DeviceUnregistration:
		// Delete monitor
		m.Nsp.StopDeviceMonitor(&event)
	}
	// Dispatch event
	m.Nsp.DispatchEvent(&event)
}

// traceDeviceNetnsUpdate - Traces a device netns update
func traceDeviceNetnsUpdate(data []byte, m *base.Monitor) {
	var eventRaw model.DeviceNetnsUpdateRaw
	if err := binary.Read(bytes.NewBuffer(data), utils.GetHostByteOrder(), &eventRaw); err != nil {
		netLogger.Errorf("failed to decode received data (DeviceNetnsUpdateRaw): %s\n", err)
		return
	}
	// Prepare event
	event := model.DeviceNetnsUpdate{
		EventBase: model.EventBase{
			EventMonitorName: m.Name,
			EventType:        model.DeviceNetnsUpdateType,
			Timestamp:        m.Nsp.GetBootTime().Add(time.Duration(eventRaw.Metadata.TimestampRaw) * time.Nanosecond),
			TTYName:          C.GoString((*C.char)(unsafe.Pointer(&eventRaw.Metadata.TTYNameRaw))),
		},
		DeviceNetnsUpdateRaw: &eventRaw,
		DeviceName:           C.GoString((*C.char)(unsafe.Pointer(&eventRaw.Device.NameRaw))),
	}
	// Dispatch event
	m.Nsp.DispatchEvent(&event)
}
