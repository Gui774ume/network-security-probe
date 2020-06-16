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
package connection

import (
	"C"
	"bytes"
	"encoding/binary"
	"time"
	"unsafe"

	"github.com/Gui774ume/ebpf"
	"github.com/sirupsen/logrus"

	"github.com/Gui774ume/network-security-probe/pkg/model"
	"github.com/Gui774ume/network-security-probe/pkg/model/kernel"
	"github.com/Gui774ume/network-security-probe/pkg/monitor/base"
	"github.com/Gui774ume/network-security-probe/pkg/utils"
)

var (
	connLogger = logrus.WithField("package", "connection")
)

// Monitor - Network device monitor
var Monitor = base.Monitor{
	Name: model.ConnectionMonitor,
	Probes: []*base.Probe{
		&base.Probe{
			Name:        "SecurityClassifyEgressFlow",
			Enabled:     true,
			Type:        ebpf.Kprobe,
			SectionName: "kprobe/security_sk_classify_flow",
			PerfMaps: []*base.PerfMap{
				&base.PerfMap{
					PerfOutputMapName: "flows",
					DataHandler:       traceFlows,
				},
			},
		},
		&base.Probe{
			Name:        "SecuritySocketBind",
			Enabled:     true,
			Type:        ebpf.Kprobe,
			SectionName: "kprobe/security_socket_bind",
		},
		&base.Probe{
			Name:        "SockGenCookie",
			Enabled:     true,
			Type:        ebpf.Kprobe,
			SectionName: "kprobe/sock_gen_cookie",
		},
		&base.Probe{
			Name:        "SockGenCookieRet",
			Enabled:     true,
			Type:        ebpf.Kprobe,
			SectionName: "kretprobe/sock_gen_cookie",
		},
	},
}

// traceFlows - Traces network flows
func traceFlows(data []byte, m *base.Monitor) {
	var eventRaw model.FlowRaw
	if err := binary.Read(bytes.NewBuffer(data), utils.GetHostByteOrder(), &eventRaw); err != nil {
		connLogger.Errorf("failed to decode received data (FlowRaw): %s\n", err)
		return
	}
	// Prepare event
	event := model.Flow{
		EventBase: model.EventBase{
			EventMonitorName: m.Name,
			EventType:        model.FlowType,
			Timestamp:        m.Nsp.GetBootTime().Add(time.Duration(eventRaw.Metadata.TimestampRaw) * time.Nanosecond),
			TTYName:          C.GoString((*C.char)(unsafe.Pointer(&eventRaw.Metadata.TTYNameRaw))),
		},
		FlowRaw: &eventRaw,
	}

	switch kernel.SocketFamily(event.Family) {
	case kernel.AFInet:
		event.Addr = utils.Uint64ToIPv4(eventRaw.AddrRaw[0])
	case kernel.AFInet6:
		event.Addr = utils.Uint64sToIPv6(eventRaw.AddrRaw)
	}
	// Dispatch event
	m.Nsp.DispatchEvent(&event)
}
