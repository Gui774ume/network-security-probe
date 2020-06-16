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
package docker

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	godocker "docker.io/go-docker"
	"docker.io/go-docker/api/types"
	"docker.io/go-docker/api/types/events"
	"docker.io/go-docker/api/types/filters"
	"github.com/Gui774ume/ebpf"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/Gui774ume/network-security-probe/pkg/config"
	"github.com/Gui774ume/network-security-probe/pkg/model"
	"github.com/Gui774ume/network-security-probe/pkg/utils"
)

var (
	dockerLogger = logrus.WithField("package", "docker")
)

// DMonitor - Docker event Monitor
var DMonitor Monitor = Monitor{
	Name: model.DockerMonitor,
}

// Monitor - Docker event monitor structure
type Monitor struct {
	Name                  model.MonitorName
	Nsp                   model.NSPInterface
	k8sClientSet          *kubernetes.Clientset
	wg                    *sync.WaitGroup
	config                *config.NSPConfig
	collection            *ebpf.Collection
	Client                *godocker.Client
	EventsContext         context.Context
	EventsCancel          context.CancelFunc
	eventStreamRetries    int
	eventStreamMaxRetries int
}

// GetName - Returns the monitor name
func (m *Monitor) GetName() model.MonitorName {
	return m.Name
}

// Init - Initialize Docker event monitor
func (m *Monitor) Init(nsp model.NSPInterface) error {
	m.eventStreamMaxRetries = 5
	m.Nsp = nsp
	m.wg = nsp.GetWaitGroup()
	m.config = nsp.GetConfig()
	m.collection = nsp.GetCollection()
	// Prepare Docker client
	var err error
	m.Client, err = godocker.NewEnvClient()
	if err != nil {
		return err
	}
	m.EventsContext, m.EventsCancel = context.WithCancel(context.Background())
	// Prepare kubernetes client
	m.k8sClientSet, err = kubernetes.NewForConfig(nsp.GetKubeConfig())
	if err != nil {
		return err
	}
	return nil
}

// Start - Start event monitor
func (m *Monitor) Start() error {
	// Subscribe to docker events
	go m.listenForDockerEvents()
	// List already running containers
	containers, err := m.Client.ContainerList(context.Background(), types.ContainerListOptions{})
	if err != nil {
		return err
	}
	// Resolve container namespaces and add update data tree
	dockerLogger.Debugf("%v monitor is running", m.GetName())
	// Create container events for already running containers
	for _, c := range containers {
		cdata, err := m.createContainerEventFromContainerID(c.ID)
		if err != nil {
			continue
		}
		cdata.Timestamp = time.Now()
		cdata.EventType = model.ContainerRunningEventType
		if err := m.filterAndDispatchEvent(cdata); err != nil {
			dockerLogger.Errorf("Docker dispatch error: %v", err)
		}
	}
	return nil
}

// listenForDockerEvents - Listens for Docker events
func (m *Monitor) listenForDockerEvents() {
	m.wg.Add(1)
	filter := filters.NewArgs()
	filter.Add("type", events.NetworkEventType)
	filter.Add("type", events.ContainerEventType)
	msgs, errs := m.Client.Events(m.EventsContext, types.EventsOptions{
		Filters: filter,
	})
	for {
		select {
		case err := <-errs:
			// Event stream was cancelled, shutting down
			if err == context.Canceled {
				m.wg.Done()
				return
			}
			// Re-subscribed to events stream
			dockerLogger.Errorf("Docker monitor: %v", err)
			m.eventStreamRetries++
			if m.eventStreamRetries >= m.eventStreamMaxRetries {
				dockerLogger.Errorf("Docker event monitor max retries reached")
				m.wg.Done()
				return
			}
			m.wg.Done()
			m.listenForDockerEvents()
			return
		case msg := <-msgs:
			// Reset eventStreamRetries
			m.eventStreamRetries = 0
			switch msg.Type {
			case events.ContainerEventType:
				if err := m.handleContainerEvent(msg); err != nil {
					dockerLogger.Warnf("Docker monitor error: %v", err)
				}
			case events.NetworkEventType:
				if err := m.handleNetworkEvent(msg); err != nil {
					dockerLogger.Warnf("Docker monitor error: %v", err)
				}
			default:
				dockerLogger.Warnf("unknown Docker event type: %v", msg.Type)
			}

		}
	}
}

// handleContainerEvent - Handle a container event
func (m *Monitor) handleContainerEvent(msg events.Message) error {
	// Parse action
	var cmd string
	var args []string
	probeEventType := model.UnknownEventType
	switch msg.Action {
	case "create":
		probeEventType = model.ContainerCreatedEventType
	case "attach":
		probeEventType = model.ContainerAttachEventType
	case "start":
		probeEventType = model.ContainerRunningEventType
	case "destroy":
		probeEventType = model.ContainerDestroyedEventType
	case "die", "kill", "stop":
		probeEventType = model.ContainerExitedEventType
	default:
		// Look for exec_create or exec_start events
		splittedAction := strings.Split(msg.Action, ": ")
		switch splittedAction[0] {
		case "exec_start":
			probeEventType = model.ContainerExecEventType
			splittedCmd := strings.Split(splittedAction[1], " ")
			cmd = splittedCmd[0]
			args = splittedCmd[1:]
		default:
			// Return, we don't care about this event
			return nil
		}
	}
	// Create the container event
	var cdata *model.ContainerEvent
	var err error
	switch probeEventType {
	case model.ContainerDestroyedEventType, model.ContainerExitedEventType:
		cdata = m.createContainerDestroyedEvent(msg)
	default:
		cdata, err = m.createContainerEventFromContainerID(msg.ID)
		if err != nil {
			return err
		}
	}
	cdata.EventType = probeEventType
	if probeEventType == model.ContainerExecEventType {
		cdata.CommandPath = cmd
		cdata.CommandArgs = args
	}
	cdata.Timestamp = time.Unix(0, msg.TimeNano)
	return m.filterAndDispatchEvent(cdata)
}

// handleNetworkEvent - handle a network event
func (m *Monitor) handleNetworkEvent(msg events.Message) error {
	probeEventType := model.UnknownEventType
	switch msg.Action {
	case "connect":
		probeEventType = model.ContainerConnectEventType
	case "disconnect":
		probeEventType = model.ContainerDisconnectEventType
	}
	cdata, err := m.createContainerEventFromContainerID(msg.Actor.Attributes["container"])
	if err != nil {
		return err
	}
	cdata.EventType = probeEventType
	cdata.Timestamp = time.Unix(0, msg.TimeNano)
	return m.filterAndDispatchEvent(cdata)
}

// Stop - Stop event monitor
func (m *Monitor) Stop() error {
	// Cancel event subscription
	m.EventsCancel()
	return nil
}

// filterAndDispatchEvent - Filters and dispatch the container event
func (m *Monitor) filterAndDispatchEvent(event *model.ContainerEvent) error {
	// Dispatch container event
	m.Nsp.DispatchEvent(event)
	return nil
}

// createContainerDestroyedEvent - Create a container "destroyed" event
func (m *Monitor) createContainerDestroyedEvent(msg events.Message) *model.ContainerEvent {
	return &model.ContainerEvent{
		EventBase: model.EventBase{
			EventType:        model.ContainerDestroyedEventType,
			EventMonitorName: m.Name,
		},
		ContainerID:   msg.ID,
		Image:         msg.Actor.Attributes["image"],
		ContainerName: msg.Actor.Attributes["name"],
	}
}

// createContainerEventFromContainerID - Creates a container event (empty action) based on a container ID
func (m *Monitor) createContainerEventFromContainerID(containerID string) (*model.ContainerEvent, error) {
	// Fetch information about the container
	cConfig, err := m.Client.ContainerInspect(context.Background(), containerID)
	if err != nil {
		return nil, err
	}
	pid := uint32(cConfig.ContainerJSONBase.State.Pid)
	exitTime, err := time.Parse(time.RFC3339Nano, cConfig.State.FinishedAt)
	if err != nil {
		fmt.Println(cConfig.State.FinishedAt, err)
		exitTime = time.Time{}
	}
	startTime, err := time.Parse(time.RFC3339Nano, cConfig.State.StartedAt)
	if err != nil {
		startTime = time.Time{}
	}
	image, tag := m.getImageAndTag(cConfig)
	return &model.ContainerEvent{
		EventBase: model.EventBase{
			EventType:        model.UnknownEventType,
			EventMonitorName: m.Name,
		},
		InitPid:             pid,
		Pidns:               utils.GetPidnsFromPid(pid),
		Cgroup:              utils.GetCgroupFromPid(pid),
		Mntns:               utils.GetMntnsFromPid(pid),
		Netns:               utils.GetNetnsFromPid(pid),
		Userns:              utils.GetUsernsFromPid(pid),
		ContainerName:       cConfig.Name[1:],
		ContainerID:         containerID,
		Image:               image,
		K8sLabelImage:       strings.Replace(image, "/", "_", -1),
		Tag:                 tag,
		Digest:              cConfig.Image,
		Privileged:          cConfig.HostConfig.Privileged,
		CapAdd:              cConfig.HostConfig.CapAdd,
		AppArmorProfile:     cConfig.AppArmorProfile,
		StartedAt:           startTime,
		FinishedAt:          exitTime,
		PortBindings:        cConfig.HostConfig.PortBindings,
		SecurityOpt:         cConfig.HostConfig.SecurityOpt,
		CommandPath:         cConfig.Path,
		CommandArgs:         cConfig.Args,
		OverlayFsMergedPath: cConfig.GraphDriver.Data["MergedDir"],
		Resources:           cConfig.HostConfig.Resources,
		NetworkSettings:     cConfig.NetworkSettings,
		MountPoints:         cConfig.Mounts,
		Labels:              cConfig.Config.Labels,
	}, nil
}

// getImageAndTag - Returns the image and tag of the container. Queries K8s when necessary
func (m *Monitor) getImageAndTag(cConfig types.ContainerJSON) (string, string) {
	// Handle k8s container
	var image, tag, imageStr string
	name, ok := cConfig.Config.Labels["io.kubernetes.pod.name"]
	if ok {
		namespace := cConfig.Config.Labels["io.kubernetes.pod.namespace"]
		containerName := cConfig.Config.Labels["io.kubernetes.container.name"]
		pod, err := m.k8sClientSet.CoreV1().Pods(namespace).Get(name, metav1.GetOptions{})
		if err == nil {
			for _, container := range pod.Spec.Containers {
				// Extract name
				splittedImage := strings.Split(container.Image, ":")
				if len(splittedImage) == 0 {
					continue
				}
				splittedImage = strings.Split(splittedImage[0], "/")
				splittedLen := len(splittedImage)
				if splittedLen > 0 {
					if splittedImage[splittedLen-1] == containerName {
						imageStr = container.Image
					}
				}
			}
		}
	}
	if imageStr == "" {
		imageStr = cConfig.Config.Image
	}
	// Normal docker container
	splittedImage := strings.Split(imageStr, ":")
	image = splittedImage[0]
	tag = ""
	if len(splittedImage) > 1 {
		tag = splittedImage[1]
	}
	return image, tag
}
