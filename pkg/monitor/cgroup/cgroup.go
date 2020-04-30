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
