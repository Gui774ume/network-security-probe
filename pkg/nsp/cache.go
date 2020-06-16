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
package nsp

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/Gui774ume/network-security-probe/pkg/config"
	"github.com/Gui774ume/network-security-probe/pkg/model"
)

// processArrayCache - Cache used process entries
type processArrayCache struct {
	entries               []*model.ProcessCacheEntry
	processReuseThreshold int64
}

func newPidArrayCache(size uint32) *processArrayCache {
	return &processArrayCache{
		entries: make([]*model.ProcessCacheEntry, int(size)),
	}
}

// lookupPid - Returns an existing or create the pid's cache entry
func (cache *processArrayCache) LookupPid(pid uint32, evtTs time.Time) (*model.ProcessCacheEntry, bool, error) {
	if pid == 0 || int(pid) > len(cache.entries) {
		return nil, false, fmt.Errorf("(processArrayCache) invalid pid for lookup: %d", pid)
	}
	inCache := false
	var entry *model.ProcessCacheEntry
	for {
		var old *model.ProcessCacheEntry
		entry = cache.entries[pid-1]
		if entry != nil {
			if entry.ExitTime == nil || (evtTs.Before(entry.ExitTime.Add(100 * time.Millisecond))) {
				inCache = entry.IsInCache()
				break
			}
			old = entry
		}
		entry = &model.ProcessCacheEntry{}
		if atomic.CompareAndSwapPointer(
			(*unsafe.Pointer)(unsafe.Pointer(&cache.entries[pid-1])),
			unsafe.Pointer(old),
			unsafe.Pointer(entry)) {
			break
		}
	}
	return entry, inCache, nil
}

type namespaceMapCache struct {
	sync.Mutex
	entries map[uint64]*model.NamespaceCacheEntry
}

func newNamespaceMapCache() *namespaceMapCache {
	return &namespaceMapCache{
		Mutex:   sync.Mutex{},
		entries: make(map[uint64]*model.NamespaceCacheEntry),
	}
}

// LookupNamespace - Returns an existing or create the netns cache entry
func (cache *namespaceMapCache) LookupNamespace(netns uint64, evtTs time.Time) (*model.NamespaceCacheEntry, bool) {
	cache.Lock()
	entry, ok := cache.entries[netns]
	inCache := ok
	if !ok || entry.ExitTime != nil && evtTs.After(entry.ExitTime.Add(100*time.Millisecond)) {
		entry = &model.NamespaceCacheEntry{}
		cache.entries[netns] = entry
	}
	if ok {
		inCache = entry.IsInCache()
	}
	cache.Unlock()
	return entry, inCache
}

// Cache - Probe manager cache
type Cache struct {
	HostNetns      uint64
	ProcessCache   *processArrayCache
	NamespaceCache *namespaceMapCache
}

// NewCache - Creates a new cache
func NewCache(config *config.NSPConfig, hostNetns uint64) *Cache {
	cache := &Cache{
		ProcessCache:   newPidArrayCache(config.CLI.ProcessCacheSize),
		NamespaceCache: newNamespaceMapCache(),
	}
	hostNsEntry, _ := cache.NamespaceCache.LookupNamespace(hostNetns, time.Now())
	hostNsEntry.Name = "host"
	hostNsEntry.Base = "host"
	hostNsEntry.ID = "host"
	hostNsEntry.Digest = "host"
	currentPidEntry, _, _ := cache.ProcessCache.LookupPid(uint32(os.Getpid()), time.Now())
	now := time.Now()
	currentPidEntry.ExecveTime = &now
	currentPidEntry.ForkTime = &now
	return cache
}

// EnrichEvent - Enrich event with process and container data. This function will return false
// if either the namespace or the process weren't in cache, or if they were in cache but aren't
// linked to a container or a process yet. Whatever the initial state of the cache, when this
// function returns, a new entry in cache will be created and ready to be used.
func (cache *Cache) EnrichEvent(event model.ProbeEvent) bool {
	// Check if the cache entry has already been set by a previous round
	nsEntry := event.GetNamespaceCacheData()
	nsInCache := true
	if nsEntry == nil {
		// Find or create the container namespace cache entry
		nsEntry, nsInCache = cache.NamespaceCache.LookupNamespace(event.GetNetns(), event.GetTimestamp())
		event.SetNamespaceCacheData(nsEntry)
	}
	switch event.GetEventType() {
	case model.ContainerRunningEventType:
		containerEvt := event.(*model.ContainerEvent)
		// If this event is a container creation event, update the cache
		nsEntry.Lock()
		nsEntry.Name = containerEvt.ContainerName
		nsEntry.ID = containerEvt.ContainerID
		nsEntry.Base = containerEvt.Image
		nsEntry.Digest = containerEvt.Digest
		nsEntry.Pod = containerEvt.Labels["io.kubernetes.pod.name"]
		nsEntry.Namespace = containerEvt.Labels["io.kubernetes.pod.namespace"]
		nsEntry.Unlock()
		return true
	case model.ContainerDestroyedEventType:
		containerEvt := event.(*model.ContainerEvent)
		// If this event is a container deletion event, set the exit time in cache
		exitTime := containerEvt.FinishedAt
		nsEntry.Lock()
		nsEntry.ExitTime = &exitTime
		nsEntry.Unlock()
		return true
	default:
		// Check if the cache entry has already been set by a previous round
		pEntry := event.GetProcessCacheData()
		pInCache := true
		if pEntry == nil {
			// if this isn't a container related event, also grab the process cache entry
			var err error
			pEntry, pInCache, err = cache.ProcessCache.LookupPid(event.GetPid(), event.GetTimestamp())
			if err != nil {
				return false
			}
			event.SetProcessCacheData(pEntry)
		}
		switch event.GetEventType() {
		case model.ExecEventType:
			// If this event is a process exec event, update the cache
			pEvt := event.(*model.ExecEvent)
			ts := pEvt.Timestamp
			pEntry.Lock()
			pEntry.BinaryPath = pEvt.Path
			pEntry.ExecveTime = &ts
			pEntry.Pid = pEvt.Metadata.PID
			pEntry.TTYName = pEvt.TTYName
			if pEntry.ExitTime != nil {
				if pEntry.ExitTime.Before(ts) {
					// This can happen if the process just changed namespace
					pEntry.ExitTime = nil
				}
			}
			pEntry.Unlock()
			pInCache = true
		case model.ExitEventType:
			// If this event is a process exit event, set the exit time in cache
			pEvt := event.(*model.ExecEvent)
			ts := pEvt.Timestamp
			pEntry.Lock()
			if pEntry.ExecveTime != nil {
				if pEntry.ExecveTime.Before(ts) {
					// This opposite can happen if the process just changed namespace
					pEntry.ExitTime = &ts
				}
			}
			pEntry.Unlock()
		case model.ForkEventType:
			// If this event is a fork event, prepare cache for the child process
			pEvt := event.(*model.ForkEvent)
			if pEvt.IsNewProcess() {
				childEntry, _, err := cache.ProcessCache.LookupPid(pEvt.ChildPid, pEvt.GetTimestamp())
				if err == nil {
					childEntry.Lock()
					if childEntry.ExecveTime == nil || len(childEntry.BinaryPath) == 0 {
						childEntry.BinaryPath = pEntry.BinaryPath
						childEntry.ExecveTime = pEntry.ExecveTime
						childEntry.TTYName = pEntry.TTYName
					}
					childEntry.Pid = pEvt.ChildPid
					childEntry.Ppid = pEvt.Metadata.PID
					if pEntry.BinaryPath != "" {
						childEntry.Parent = pEntry
					}
					ts := pEvt.Timestamp
					childEntry.ForkTime = &ts
					childEntry.Unlock()
				}
			}
		}
		return nsInCache && pInCache
	}
}
