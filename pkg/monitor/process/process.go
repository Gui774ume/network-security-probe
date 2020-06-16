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
package process

import (
	"C"
	"bytes"
	"encoding/binary"
	"time"
	"unsafe"

	"github.com/Gui774ume/ebpf"
	"github.com/shirou/gopsutil/process"
	"github.com/sirupsen/logrus"

	"github.com/Gui774ume/network-security-probe/pkg/model"
	"github.com/Gui774ume/network-security-probe/pkg/monitor/base"
	"github.com/Gui774ume/network-security-probe/pkg/utils"
)
import (
	"strings"

	"github.com/Gui774ume/network-security-probe/pkg/model/kernel"
)

var (
	processLogger = logrus.WithField("package", "process")
)

// Monitor - Network device monitor
var Monitor = base.Monitor{
	Name:         model.ProcessMonitor,
	SnapshotFunc: listRunningProcesses,
	Probes: []*base.Probe{
		&base.Probe{
			Name:        "ProcessFork",
			Enabled:     true,
			Type:        ebpf.Kprobe,
			SectionName: "kprobe/_do_fork",
		},
		&base.Probe{
			Name:        "SchedProcessFork",
			Enabled:     true,
			Type:        ebpf.TracePoint,
			SectionName: "tracepoint/sched/sched_process_fork",
			PerfMaps: []*base.PerfMap{
				&base.PerfMap{
					PerfOutputMapName: "fork_events",
					DataHandler:       traceForkEvents,
				},
			},
		},
		&base.Probe{
			Name:        "SchedProcessExec",
			Enabled:     true,
			Type:        ebpf.TracePoint,
			SectionName: "tracepoint/sched/sched_process_exec",
			PerfMaps: []*base.PerfMap{
				&base.PerfMap{
					PerfOutputMapName: "exec_events",
					DataHandler:       traceExecEvents,
				},
			},
		},
		&base.Probe{
			Name:        "SchedProcessExit",
			Enabled:     true,
			Type:        ebpf.TracePoint,
			SectionName: "tracepoint/sched/sched_process_exit",
		},
	},
}

// listRunningProcesses - List all running processes
func listRunningProcesses(m *base.Monitor) error {
	list, err := process.Processes()
	if err != nil {
		return err
	}
	for _, p := range list {
		binaryPath, _ := p.Exe()
		ppidRaw, _ := p.Ppid()
		ppid := uint32(ppidRaw)
		pid := uint32(p.Pid)
		execTime, _ := p.CreateTime()
		tty, _ := p.Terminal()
		tty = strings.Replace(tty, "/", "", -1)
		if ppid > 0 {
			forkEvent := &model.ForkEvent{
				EventBase: model.EventBase{
					EventType:        model.ForkEventType,
					EventMonitorName: m.Name,
					Timestamp:        time.Unix(0, execTime*int64(time.Millisecond)),
				},
				ForkRaw: &model.ForkRaw{
					Metadata: model.Metadata{
						Pidns: utils.GetPidnsFromPid(ppid),
						Netns: utils.GetNetnsFromPid(ppid),
						PID:   ppid,
						TID:   ppid,
					},
					ChildPid:   pid,
					CloneFlags: uint64(kernel.SIGCHLD),
				},
			}
			m.Nsp.DispatchEvent(forkEvent)
		}
		execveEvent := &model.ExecEvent{
			EventBase: model.EventBase{
				EventType:        model.ExecEventType,
				EventMonitorName: m.Name,
				Timestamp:        time.Unix(0, execTime*int64(time.Millisecond)),
				TTYName:          tty,
			},
			ExecRaw: &model.ExecRaw{
				Metadata: model.Metadata{
					Pidns: utils.GetPidnsFromPid(pid),
					Netns: utils.GetNetnsFromPid(pid),
					PID:   pid,
					TID:   pid,
				},
				Type: model.Execve,
			},
			Path: binaryPath,
		}
		m.Nsp.DispatchEvent(execveEvent)
	}
	return nil
}

// traceForkEvents - Traces fork events
func traceForkEvents(data []byte, m *base.Monitor) {
	var eventRaw model.ForkRaw
	if err := binary.Read(bytes.NewBuffer(data), utils.GetHostByteOrder(), &eventRaw); err != nil {
		processLogger.Errorf("failed to decode received data (ForkEventRaw): %s\n", err)
		return
	}
	// Prepare event
	event := model.ForkEvent{
		EventBase: model.EventBase{
			EventMonitorName: m.Name,
			EventType:        model.ForkEventType,
			Timestamp:        m.Nsp.GetBootTime().Add(time.Duration(eventRaw.Metadata.TimestampRaw) * time.Nanosecond),
			TTYName:          C.GoString((*C.char)(unsafe.Pointer(&eventRaw.Metadata.TTYNameRaw))),
		},
		ForkRaw: &eventRaw,
	}

	// Dispatch event
	m.Nsp.DispatchEvent(&event)
}

// traceExecEvents - Traces fork events
func traceExecEvents(data []byte, m *base.Monitor) {
	var eventRaw model.ExecRaw
	if err := binary.Read(bytes.NewBuffer(data), utils.GetHostByteOrder(), &eventRaw); err != nil {
		processLogger.Errorf("failed to decode received data (ExecEventRaw): %s\n", err)
		return
	}
	// Prepare event
	event := model.ExecEvent{
		EventBase: model.EventBase{
			EventMonitorName: m.Name,
			EventType:        eventRaw.ResolveEventType(),
			Timestamp:        m.Nsp.GetBootTime().Add(time.Duration(eventRaw.Metadata.TimestampRaw) * time.Nanosecond),
			TTYName:          C.GoString((*C.char)(unsafe.Pointer(&eventRaw.Metadata.TTYNameRaw))),
		},
		ExecRaw: &eventRaw,
		Path:    C.GoString((*C.char)(unsafe.Pointer(&eventRaw.PathRaw))),
	}

	// Dispatch event
	m.Nsp.DispatchEvent(&event)
}
