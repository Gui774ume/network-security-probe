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
package cgroup

import (
	"C"

	"github.com/Gui774ume/ebpf"
	"github.com/sirupsen/logrus"

	"github.com/Gui774ume/network-security-probe/pkg/model"
	"github.com/Gui774ume/network-security-probe/pkg/monitor/base"
)

var (
	cgroupLogger = logrus.WithField("package", "cgroup")
)

// Monitor - Network device monitor
var Monitor = base.Monitor{
	Name: model.CgroupMonitor,
	Probes: []*base.Probe{
		&base.Probe{
			Name:        "CgroupSocketOpen",
			Enabled:     false,
			Type:        ebpf.CGroupSock,
			SectionName: "cgroup/sock/sock",
			CgroupPath:  "/sys/fs/cgroup/unified",
		},
		&base.Probe{
			Name:        "CgroupIngress",
			Enabled:     false,
			Type:        ebpf.CGroupSKB,
			SectionName: "cgroup/skb/ingress",
			CgroupPath:  "/sys/fs/cgroup/unified",
		},
		&base.Probe{
			Name:        "CgroupEgress",
			Enabled:     false,
			Type:        ebpf.CGroupSKB,
			SectionName: "cgroup/skb/egress",
			CgroupPath:  "/sys/fs/cgroup/unified",
		},
		&base.Probe{
			Name:        "SockOps",
			Enabled:     false,
			Type:        ebpf.SockOps,
			SectionName: "sockops/op",
			CgroupPath:  "/sys/fs/cgroup/unified",
		},
	},
}
