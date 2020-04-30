package profileloader

import (
	"bytes"
	"reflect"
	"sync"
	"time"
	"unsafe"

	"github.com/Gui774ume/ebpf"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/apimachinery/pkg/types"

	v1 "github.com/Gui774ume/network-security-probe/pkg/k8s/apis/securityprobe.datadoghq.com/v1"
	spclientset "github.com/Gui774ume/network-security-probe/pkg/k8s/client/clientset/versioned"
	"github.com/Gui774ume/network-security-probe/pkg/model"
	"github.com/Gui774ume/network-security-probe/pkg/processor/profileloader/keyvalue"
	"github.com/Gui774ume/network-security-probe/pkg/utils"
)

var (
	profileLoaderLogger = logrus.WithField("package", "processor")
)

// ProfileVersion - Profile unique key
type ProfileVersion struct {
	UID             types.UID
	ResourceVersion string
}

// HasSameUID - Returns true if the UIDs match
func (pv ProfileVersion) HasSameUID(otherPV ProfileVersion) bool {
	return pv.UID == otherPV.UID
}

// HasSameResourceVersion - Returns true if the ResourceVersions match
func (pv ProfileVersion) HasSameResourceVersion(otherPV ProfileVersion) bool {
	return pv.ResourceVersion == otherPV.ResourceVersion
}

// Equals - Returns true if the two ProfileVersion are identical
func (pv ProfileVersion) Equals(otherPV ProfileVersion) bool {
	return pv.HasSameUID(otherPV) && pv.HasSameResourceVersion(otherPV)
}

// IsEmpty - Returns true if the UID and the ResourceVersion are empty
func (pv ProfileVersion) IsEmpty() bool {
	return pv.UID == types.UID("") && pv.ResourceVersion == ""
}

// ProfileVersionSet - Defines a unique set of ProfileVersion
type ProfileVersionSet []ProfileVersion

// Add - Adds a new ProfileVersion to the set
func (pvs *ProfileVersionSet) Add(profileVersion ProfileVersion) {
	for _, pv := range *pvs {
		if pv.Equals(profileVersion) {
			return
		}
	}
	*pvs = append(*pvs, profileVersion)
}

// ProfileMetadata - Keeps track of the usage of a profile at runtime
type ProfileMetadata struct {
	ProfileVersion ProfileVersion
	Profile        *v1.SecurityProfile
	ContainerIDs   []string
}

// RemoveContainerID - Removes a container ID from the list of container IDs
func (pm *ProfileMetadata) RemoveContainerID(containerID string) {
	for i, v := range pm.ContainerIDs {
		if v == containerID {
			pm.ContainerIDs = append(pm.ContainerIDs[:i], pm.ContainerIDs[i+1:]...)
			break
		}
	}
}

// AddContainerID - Appends a container ID to the list of containers of
// this profile, only if it is not already in the list.
func (pm *ProfileMetadata) AddContainerID(containerID string) {
	// Check if the contaierID is already in the list
	for _, id := range pm.ContainerIDs {
		if id == containerID {
			return
		}
	}
	pm.ContainerIDs = append(pm.ContainerIDs, containerID)
}

// ContainerMetadata - Keeps track of the running containers
type ContainerMetadata struct {
	ContainerID    string
	ProfileVersion ProfileVersion
	Image          string
	Tag            string
	Pod            string
	Namespace      string
	Labels         labels.Labels
	Netns          uint64
	Pidns          uint64
}

// ProfileLoader - ProfileLoader processor
type ProfileLoader struct {
	nsp                    model.NSPInterface
	wg                     *sync.WaitGroup
	collection             *ebpf.Collection
	stop                   chan struct{}
	EventChan              chan model.ProbeEvent
	SecurityProbeClientSet *spclientset.Clientset
	LoadedProfiles         map[ProfileVersion]*ProfileMetadata
	RunningContainers      map[string]*ContainerMetadata
	MapIDMapName           map[uint32]string
}

// GetName - Returns the processor name
func (pl *ProfileLoader) GetName() model.ProcessorName {
	return model.ProfileLoaderProcessor
}

// GetEventChan - Returns event channel
func (pl *ProfileLoader) GetEventChan() chan model.ProbeEvent {
	return pl.EventChan
}

// Start - Starts tracer
func (pl *ProfileLoader) Start(nsp model.NSPInterface) error {
	var err error
	pl.MapIDMapName = map[uint32]string{}
	pl.nsp = nsp
	pl.LoadedProfiles = map[ProfileVersion]*ProfileMetadata{}
	pl.RunningContainers = map[string]*ContainerMetadata{}
	pl.wg = nsp.GetWaitGroup()
	pl.collection = nsp.GetCollection()
	pl.EventChan = make(chan model.ProbeEvent, nsp.GetConfig().EBPF.MapsChannelLength)
	pl.stop = make(chan struct{})
	// Create k8s client
	pl.SecurityProbeClientSet, err = spclientset.NewForConfig(nsp.GetKubeConfig())
	if err != nil {
		return err
	}
	go pl.listen()
	return nil
}

// listen - Wait for events and print them
func (pl *ProfileLoader) listen() {
	pl.wg.Add(1)
	var event model.ProbeEvent
	var ok bool
	for {
		select {
		case <-pl.stop:
			pl.wg.Done()
			return
		case event, ok = <-pl.EventChan:
			if !ok {
				pl.wg.Done()
				return
			}
			switch event.GetEventType() {
			case model.ContainerRunningEventType:
				if err := pl.handleContainerRunning(event.(*model.ContainerEvent)); err != nil {
					profileLoaderLogger.Warn(err)
				}
				break
			case model.ContainerExitedEventType:
				if err := pl.handleContainerExited(event.(*model.ContainerEvent)); err != nil {
					profileLoaderLogger.Warn(err)
				}
				break
			case model.SecurityProfileUpdatedType:
				if err := pl.handleSecurityProfileUpdate(event.(*model.SecurityProfileUpdatedEvent)); err != nil {
					profileLoaderLogger.Warn(err)
				}
				break
			case model.SecurityProfileCreatedType:
				if err := pl.handleSecurityProfileCreation(event.(*model.SecurityProfileCreatedEvent)); err != nil {
					profileLoaderLogger.Warn(err)
				}
				break
			case model.SecurityProfileDeletedType:
				if err := pl.handleSecurityProfileDeletion(event.(*model.SecurityProfileDeletedEvent)); err != nil {
					profileLoaderLogger.Warn(err)
				}
				break
			}
		}
	}
}

// Stop - Stop tracer
func (pl *ProfileLoader) Stop() error {
	close(pl.stop)
	close(pl.EventChan)
	return nil
}

// handleContainerRunning - Handles a container running event
func (pl *ProfileLoader) handleContainerRunning(event *model.ContainerEvent) error {
	labelSelector := metav1.LabelSelector{}
	pod := event.Labels["io.kubernetes.pod.name"]
	namespace, ok := event.Labels["io.kubernetes.pod.namespace"]
	if !ok {
		namespace = "default"
		labelSelector.MatchLabels = map[string]string{
			"image": event.K8sLabelImage,
		}
		if event.Tag != "" {
			labelSelector.MatchLabels["tag"] = event.Tag
		}
	} else {
		app, ok := event.Labels["app"]
		if !ok {
			labelSelector.MatchLabels = map[string]string{
				"pod":       pod,
				"namespace": namespace,
			}
		} else {
			labelSelector.MatchLabels = map[string]string{
				"app": app,
			}
		}
	}
	// Save running container metadata
	container := ContainerMetadata{
		ContainerID: event.ContainerID,
		Image:       event.Image,
		Tag:         event.Tag,
		Pod:         pod,
		Namespace:   namespace,
		Netns:       event.Netns,
		Pidns:       event.Pidns,
		Labels:      labels.Set(labelSelector.MatchLabels),
	}
	pl.RunningContainers[event.ContainerID] = &container
	// Look for the security profile
	profiles, err := pl.SecurityProbeClientSet.SecurityprobeV1().SecurityProfiles(namespace).List(metav1.ListOptions{
		LabelSelector: labels.Set(labelSelector.MatchLabels).String(),
		Limit:         1,
	})
	if err != nil {
		return err
	}
	if len(profiles.Items) == 0 {
		// return fmt.Errorf("No security profile found for %v %v:%v", labelSelector.MatchLabels, event.Image, event.Tag)
		return nil
	}
	profileLoaderLogger.Debugf("Applying security profile %s to workload %v", profiles.Items[0].UID, labelSelector.MatchLabels)
	profileVersion := ProfileVersion{
		UID:             profiles.Items[0].UID,
		ResourceVersion: profiles.Items[0].ResourceVersion,
	}
	profile, ok := pl.LoadedProfiles[profileVersion]
	if !ok {
		profile = &ProfileMetadata{
			ProfileVersion: profileVersion,
			Profile:        &profiles.Items[0],
			ContainerIDs:   []string{},
		}
	}
	if err := pl.CommitSecurityProfile(profile, &container); err != nil {
		return err
	}
	pl.LoadedProfiles[profile.ProfileVersion] = profile
	return nil
}

// handleContainerExited - Handles a container running event
func (pl *ProfileLoader) handleContainerExited(event *model.ContainerEvent) error {
	// select container
	container, ok := pl.RunningContainers[event.ContainerID]
	if !ok {
		// Nothing to delete
		return nil
	}
	// select profile
	profile, ok := pl.LoadedProfiles[container.ProfileVersion]
	if ok {
		// Unset the binding between the container and its profile
		if err := pl.DeleteProfileMappings(profile, container); err != nil {
			return errors.Wrap(err, "couldn't delete profile mappings")
		}
		// Delete container from the list of containers of the profile
		profile.RemoveContainerID(container.ContainerID)
		if len(profile.ContainerIDs) <= 0 {
			// Delete profile from kernel
			if err := pl.DeleteSecurityProfile(profile.Profile); err != nil {
				return errors.Wrapf(err, "couldn't delete security profile %s", profile.ProfileVersion.UID)
			}
			delete(pl.LoadedProfiles, container.ProfileVersion)
		}
	}
	// Delete container ID
	delete(pl.RunningContainers, event.ContainerID)
	return nil
}

// handleSecurityProfileUpdate - Handles a security profile creation
func (pl *ProfileLoader) handleSecurityProfileCreation(event *model.SecurityProfileCreatedEvent) error {
	return pl.handleNewSecurityProfile(event.Profile)
}

// handleSecurityProfileUpdate - Handles a security profile update
func (pl *ProfileLoader) handleSecurityProfileUpdate(event *model.SecurityProfileUpdatedEvent) error {
	return pl.handleNewSecurityProfile(event.New)
}

// handleSecurityProfileUpdate - Handles a security profile update
func (pl *ProfileLoader) handleNewSecurityProfile(eventProfile *v1.SecurityProfile) error {
	newPV := ProfileVersion{
		UID:             eventProfile.UID,
		ResourceVersion: eventProfile.ResourceVersion,
	}
	profile := ProfileMetadata{
		ProfileVersion: newPV,
		Profile:        eventProfile,
		ContainerIDs:   []string{},
	}
	selector := labels.NewSelector()
	for label, value := range eventProfile.Labels {
		req, err := labels.NewRequirement(
			label,
			selection.In,
			[]string{value},
		)
		if err != nil {
			return err
		}
		selector = selector.Add(*req)
	}
	// Loop through all the containers and check if their profiles need to be updated
	for _, container := range pl.RunningContainers {
		shouldCommit := false
		// Check versions
		if newPV.HasSameUID(container.ProfileVersion) && !newPV.HasSameResourceVersion(container.ProfileVersion) {
			shouldCommit = true
		}
		// If the container doesn't have a profile currently, check if its flags match the profile
		if container.ProfileVersion.IsEmpty() {
			if selector.Matches(container.Labels) {
				shouldCommit = true
			}
		}
		// Commit profile to container if applicable
		if shouldCommit {
			if err := pl.CommitSecurityProfile(&profile, container); err != nil {
				profileLoaderLogger.Warn(err)
			}
		}
	}
	// If the profile was applied to a container, add it to the list of loaded profiles
	if len(profile.ContainerIDs) > 0 {
		pl.LoadedProfiles[newPV] = &profile
	}
	return nil
}

// handleSecurityProfileDeletion - Handles a security profile deletion
func (pl *ProfileLoader) handleSecurityProfileDeletion(event *model.SecurityProfileDeletedEvent) error {
	// This resource can exist in multiple version, this list will contain all the ProfileVersions to delete.
	pvsToDelete := ProfileVersionSet{}
	// Check if the profile is used locally
	profile := ProfileMetadata{
		ProfileVersion: ProfileVersion{
			UID:             event.Profile.UID,
			ResourceVersion: event.Profile.ResourceVersion,
		},
		Profile:      event.Profile,
		ContainerIDs: []string{},
	}
	for containerID, container := range pl.RunningContainers {
		// check if the profile UID match
		if container.ProfileVersion.UID != event.Profile.UID {
			continue
		} else {
			pvsToDelete.Add(container.ProfileVersion)
		}
		// Delete profile mappings
		if err := pl.DeleteProfileMappings(&profile, container); err != nil {
			profileLoaderLogger.Warnf("couldn't delete profile mappings for containerID %s: %v", containerID, err)
			continue
		}
		container.ProfileVersion = ProfileVersion{}
	}
	// Delete all detected versions of this security profile
	for _, pv := range pvsToDelete {
		profileToDelete, ok := pl.LoadedProfiles[pv]
		if !ok {
			continue
		}
		// Delete the profile from the kernel
		if err := pl.DeleteSecurityProfile(profileToDelete.Profile); err != nil {
			profileLoaderLogger.Warnf("couldn't delete security profile %s from kernel: %v", pv.UID, err)
		}
		// Delete profile from the list of loaded profiles
		delete(pl.LoadedProfiles, pv)
	}
	return nil
}

// CommitSecurityProfile - Ensures that the provided profile is the one used by the provided container
// When necessary, will either update and / or delete the profile currently in use once the commit is done.
func (pl *ProfileLoader) CommitSecurityProfile(profile *ProfileMetadata, container *ContainerMetadata) error {
	// Decide if the profile should be inserted in the kernel
	var currentProfile *ProfileMetadata
	var ok, newVersion bool
	if container.ProfileVersion.IsEmpty() {
		currentProfile, ok = pl.LoadedProfiles[profile.ProfileVersion]
	} else {
		currentProfile, ok = pl.LoadedProfiles[container.ProfileVersion]
	}
	newVersion = ok && profile.ProfileVersion != container.ProfileVersion && !container.ProfileVersion.IsEmpty()
	if !ok || newVersion {
		if err := pl.InsertSecurityProfile(profile.Profile); err != nil {
			return errors.Wrap(err, "couldn't insert security profile in kernel")
		}
	}
	// Swap netns / pidns / process mappings
	if err := pl.SwapProfileMappings(profile, container); err != nil {
		return errors.Wrap(err, "couldn't update profile mappings")
	}
	if newVersion {
		// Delete old profile
		if err := pl.DeleteSecurityProfile(currentProfile.Profile); err != nil {
			return errors.Wrap(err, "couldn't delete security profile from the kernel")
		}
		// Remove container from the list of handled containers
		currentProfile.RemoveContainerID(container.ContainerID)
		// Check if the current profile should be delete entirely
		if len(currentProfile.ContainerIDs) <= 0 {
			delete(pl.LoadedProfiles, container.ProfileVersion)
		}
	}
	// Update container metadata
	container.ProfileVersion = profile.ProfileVersion
	// Update profile metadata
	profile.AddContainerID(container.ContainerID)
	return nil
}

// DeleteSecurityProfile - Deletes a security profile from the kernel.
func (pl *ProfileLoader) DeleteSecurityProfile(profile *v1.SecurityProfile) error {
	// Generate profile hashmap key-values
	keyValues, err := profile.Spec.GetProfileKeyValues()
	if err != nil {
		return errors.Wrap(err, "couldn't generate the profile key-values")
	}
	// Delete key values
	for _, kv := range keyValues {
		if err := pl.DeleteKeyValue(kv); err != nil {
			return err
		}
	}
	// Generate profile MapOfMaps key-values
	mmKeyValues, err := profile.Spec.GetProfileMapOfMapsKeyValue()
	if err != nil {
		return errors.Wrap(err, "couldn't generate the profile MapOfMaps key-values")
	}
	// Delete MapOfMaps key-values
	for _, kv := range mmKeyValues {
		if err := pl.DeleteMapOfMapsKeyValue(kv); err != nil {
			return err
		}
	}
	profileLoaderLogger.Debugf("Security profile %s (version %s) deleted", profile.UID, profile.ResourceVersion)
	return nil
}

// InsertSecurityProfile - Inserts a security profile in the kernel.
func (pl *ProfileLoader) InsertSecurityProfile(profile *v1.SecurityProfile) error {
	// Generate new random ids for the profile
	profile.GenerateRandomIDs()
	// Generate profile hashmap key-values
	keyValues, err := profile.Spec.GetProfileKeyValues()
	if err != nil {
		return errors.Wrap(err, "couldn't generate the profile key-values")
	}
	// Insert key values
	for _, kv := range keyValues {
		if err := pl.PutKeyValue(kv); err != nil {
			return err
		}
	}
	// Generate profile MapOfMaps key-values
	mmKeyValues, err := profile.Spec.GetProfileMapOfMapsKeyValue()
	if err != nil {
		return errors.Wrap(err, "couldn't generate the profile MapOfMaps key-values")
	}
	// Insert MapOfMaps key-values
	for _, kv := range mmKeyValues {
		if err := pl.InsertMapOfMapsKeyValue(kv); err != nil {
			return err
		}
	}
	profileLoaderLogger.Debugf("Security profile %s (version %s) inserted", profile.UID, profile.ResourceVersion)
	return nil
}

// DeleteKeyValue - Deletes a key value in the kernel
func (pl *ProfileLoader) DeleteKeyValue(kv *keyvalue.KeyValue) error {
	byteOrder := utils.GetHostByteOrder()
	// Select map
	kMap, ok := pl.collection.Maps[kv.GetMapSection()]
	if !ok {
		return errors.Wrap(errors.New(kv.GetMapSection()), "unknown map")
	}
	// Generate Key unsafe pointer
	keyPtr, err := kv.GetKey(byteOrder)
	if err != nil {
		return errors.Wrapf(err, "couldn't create unsafe pointer key for type %s", reflect.TypeOf(kv.Key))
	}
	// Insert key-value in map
	if err := kMap.Delete(keyPtr); err != nil {
		return errors.Wrapf(err, "failed to delete element in map %s", kv.GetMapSection())
	}
	return nil
}

// PutKeyValue - Inserts a key value in the kernel
func (pl *ProfileLoader) PutKeyValue(kv *keyvalue.KeyValue) error {
	byteOrder := utils.GetHostByteOrder()
	// Select map
	kMap, ok := pl.collection.Maps[kv.GetMapSection()]
	if !ok {
		return errors.Wrap(errors.New(kv.GetMapSection()), "unknown map")
	}
	// Generate Key unsafe pointer
	keyPtr, err := kv.GetKey(byteOrder)
	if err != nil {
		return errors.Wrapf(err, "couldn't create unsafe pointer key for type %s", reflect.TypeOf(kv.Key))
	}
	// Generate Value unsafe pointer
	valuePtr, err := kv.GetValue(byteOrder)
	if err != nil {
		return errors.Wrapf(err, "couldn't create unsafe pointer value for type %s", reflect.TypeOf(kv.Key))
	}
	// Insert key-value in map
	if err := kMap.Put(keyPtr, valuePtr); err != nil {
		return errors.Wrapf(err, "failed to insert element in map %s", kv.GetMapSection())
	}
	return nil
}

// DeleteMapOfMapsKeyValue - Deletes a map-of-maps key value in the kernel
func (pl *ProfileLoader) DeleteMapOfMapsKeyValue(kv *keyvalue.MapOfMapsKeyValue) error {
	byteOrder := utils.GetHostByteOrder()
	// Select map of maps
	mapOfMaps, ok := pl.collection.Maps[kv.MapOfMapsKey.GetMapSection()]
	if !ok {
		return errors.Wrap(errors.New(kv.MapOfMapsKey.GetMapSection()), "unknown map")
	}
	// Generate inner map Key unsafe pointer
	keyPtr, err := kv.MapOfMapsKey.GetKey(byteOrder)
	if err != nil {
		return errors.Wrapf(err, "couldn't create unsafe pointer key for type %s", reflect.TypeOf(kv.MapOfMapsKey))
	}
	// Fetch map id
	innerMapIDB, err := mapOfMaps.GetBytes(keyPtr)
	if err != nil {
		return errors.Wrapf(err, "inner map not found fot type %s", reflect.TypeOf(kv.MapOfMapsKey))
	}
	innerMapID := byteOrder.Uint32(innerMapIDB)
	// Delete inner map entry in the map of maps
	if err := mapOfMaps.Delete(keyPtr); err != nil {
		return errors.Wrapf(err, "failed to delete element in map %s", kv.MapOfMapsKey.GetMapSection())
	}
	// Select inner map name
	// TODO: this should be improved by querying the kernel with a BPF _ObjGetInfoByFD call
	// -> won't work for pinned map after an agent unexpected shut down and restart
	innerMapName, ok := pl.MapIDMapName[innerMapID]
	if !ok {
		return errors.Wrapf(errors.New(kv.MapSectionToClone), "unknown inner map ID %d", innerMapID)
	}
	innerMap, ok := pl.collection.Maps[innerMapName]
	if !ok {
		return errors.Wrapf(errors.New(kv.MapSectionToClone), "unknown inner map name %s", innerMapName)
	}
	// Close inner map
	if err := innerMap.Close(); err != nil {
		return errors.Wrapf(err, "couldn't close inner map for type %s", reflect.TypeOf(kv.MapOfMapsKey))
	}
	// Remove inner map from collection
	delete(pl.collection.Maps, innerMapName)
	// Remove inner map from mapping ID <-> name
	delete(pl.MapIDMapName, innerMapID)
	return nil
}

// InsertMapOfMapsKeyValue - Inserts a map-of-maps key value in the kernel
func (pl *ProfileLoader) InsertMapOfMapsKeyValue(kv *keyvalue.MapOfMapsKeyValue) error {
	byteOrder := utils.GetHostByteOrder()
	// Select inner map and clone it
	kMap, ok := pl.collection.Maps[kv.MapSectionToClone]
	if !ok {
		return errors.Wrap(errors.New(kv.MapSectionToClone), "unknown inner map")
	}
	// Clone map
	newSpec := kMap.MapSpec
	newSpec.Name = keyvalue.NewRandomMapName()
	// Create duplicated map
	newMap, err := ebpf.NewMap(newSpec)
	if err != nil {
		return errors.Wrapf(err, "couldn't duplicate map %s", kv.MapSectionToClone)
	}
	// Add map to the list of program handled by the collection
	pl.collection.Maps[newSpec.Name] = newMap
	// Insert key-values in this new map
	for _, innerKV := range kv.Keys {
		// Generate Key unsafe pointer
		keyPtr, err := innerKV.GetKey(byteOrder)
		if err != nil {
			return errors.Wrapf(err, "couldn't create unsafe pointer key for type %s", reflect.TypeOf(innerKV.Key))
		}
		// Generate Value unsafe pointer
		valuePtr, err := innerKV.GetValue(byteOrder)
		if err != nil {
			return errors.Wrapf(err, "couldn't create unsafe pointer value for type %s", reflect.TypeOf(innerKV.Key))
		}
		// Insert key-value in map
		if err := newMap.Put(keyPtr, valuePtr); err != nil {
			return errors.Wrapf(err, "failed to insert element in map %s", newSpec.Name)
		}
	}
	// Select map of maps
	mapOfMaps, ok := pl.collection.Maps[kv.MapOfMapsKey.GetMapSection()]
	if !ok {
		return errors.Wrap(errors.New(kv.MapOfMapsKey.GetMapSection()), "unknown map")
	}
	// Add new inner map entry
	keyPtr, err := kv.MapOfMapsKey.GetKey(byteOrder)
	if err != nil {
		return errors.Wrapf(err, "couldn't create unsafe pointer key for type %s", reflect.TypeOf(kv.MapOfMapsKey))
	}
	value := uint32(newMap.FD())
	if err := mapOfMaps.Put(keyPtr, unsafe.Pointer(&value)); err != nil {
		return errors.Wrapf(err, "failed to insert element in map %s", kv.MapOfMapsKey.GetMapSection())
	}
	// Retrieve inner map ID and save inner map ID <-> map name
	innerMapIDB, err := mapOfMaps.GetBytes(keyPtr)
	if err != nil {
		return errors.Wrap(err, "couldn't retrieve inner map ID")
	}
	innerMapID := byteOrder.Uint32(innerMapIDB)
	pl.MapIDMapName[innerMapID] = newSpec.Name
	return nil
}

// SwapProfileMappings - Ensures that the mappings between the profile and the container in kernel are correct.
func (pl *ProfileLoader) SwapProfileMappings(profile *ProfileMetadata, container *ContainerMetadata) error {
	// 1) Fetch old binary_ids. Any binding between a process and those cookies will need to be updated to
	// the cookies of the new profile.
	oldBinaryIDs, binaryPaths, err := pl.computeListOfBinaryIDs(container.Netns)
	if err != nil {
		return err
	}
	// 2) swap netns / pidns -> profile_id
	nsKeys, err := profile.Profile.Spec.GetProfileNSKeyValues(container.Netns, container.Pidns)
	if err != nil {
		return err
	}
	for _, kv := range nsKeys {
		if err := pl.PutKeyValue(kv); err != nil {
			return err
		}
	}
	// 3) (swap any pid -> binary_id => loop until nothing changes)
	if len(oldBinaryIDs) > 0 {
		if err := pl.swapPidBinaryID(oldBinaryIDs, binaryPaths, profile.Profile); err != nil {
			return err
		}
	}
	return nil
}

// DeleteProfileMappings - Removes the mappings between a profile and a container
func (pl *ProfileLoader) DeleteProfileMappings(profile *ProfileMetadata, container *ContainerMetadata) error {
	// 1) Fetch old binary_ids. Any binding between a process and those cookies will need to be deleted.
	oldBinaryIDs, _, err := pl.computeListOfBinaryIDs(container.Netns)
	if err != nil {
		return err
	}
	// 2) Delete netns and pidns mappings
	nsKeys, err := profile.Profile.Spec.GetProfileNSKeyValues(container.Netns, container.Pidns)
	if err != nil {
		return err
	}
	for _, kv := range nsKeys {
		if err := pl.DeleteKeyValue(kv); err != nil {
			return err
		}
	}
	// 3) Delete any entry in the pid <-> binary_id map that points to one of the cookies in oldBinaryIDs
	if len(oldBinaryIDs) > 0 {
		if err := pl.deletePidBinaryID(oldBinaryIDs, profile.Profile); err != nil {
			return err
		}
	}
	return nil
}

func (pl ProfileLoader) computeListOfBinaryIDs(netns uint64) ([]keyvalue.Cookie, []string, error) {
	oldBinaryIDs := []keyvalue.Cookie{}
	oldBinaryPaths := []string{}
	byteOrder := utils.GetHostByteOrder()
	netnsProfileIDsMap, ok := pl.collection.Maps["netns_profile_id"]
	if !ok {
		return nil, nil, errors.New("couldn't find netns_profile_id")
	}
	key := &keyvalue.NETnsKey{
		NS: netns,
	}
	keyPtr, err := key.GetUnsafePointer(byteOrder)
	if err != nil {
		return nil, nil, err
	}
	securityProfileIDB, err := netnsProfileIDsMap.GetBytes(keyPtr)
	if err != nil {
		return nil, nil, err
	}
	if len(securityProfileIDB) == 0 {
		// Nothing to do, there is nothing in the kernel for that namespace
		return oldBinaryIDs, oldBinaryPaths, nil
	}
	securityProfileID := keyvalue.Cookie(byteOrder.Uint32(securityProfileIDB))
	// Compute list of old binary_ids
	pathBinaryIDsMap, ok := pl.collection.Maps["path_binary_id"]
	if !ok {
		return nil, nil, errors.New("couldn't find pid_binary_id")
	}
	iterator := pathBinaryIDsMap.Iterate()
	var binaryPathKey keyvalue.BinaryPathKey
	var value keyvalue.CookieValue
	for iterator.Next(&binaryPathKey, &value) {
		if binaryPathKey.Cookie == securityProfileID {
			oldBinaryIDs = append(oldBinaryIDs, value.Cookie)
			oldBinaryPaths = append(oldBinaryPaths, string(bytes.Trim(binaryPathKey.Path[:], "\x00")))
		}
	}
	return oldBinaryIDs, oldBinaryPaths, nil
}

func (pl *ProfileLoader) swapPidBinaryID(oldBinaryIDs []keyvalue.Cookie, binaryPaths []string, newProfile *v1.SecurityProfile) error {
	byteOrder := utils.GetHostByteOrder()
	pidBinaryIDsMap, ok := pl.collection.Maps["pid_binary_id"]
	if !ok {
		return errors.New("couldn't find pid_binary_id")
	}
	for i := 0; i < 10; i++ {
		updateDone := true
		// loop through the pid <-> binary_id and look for old binary_id cookies
		iterator := pidBinaryIDsMap.Iterate()
		var key keyvalue.PIDKey
		var value keyvalue.CookieValue
		for iterator.Next(&key, &value) {
			if index := keyvalue.CookieListContains(oldBinaryIDs, value.Cookie); index >= 0 {
				updateDone = false
				// Fetch new cookie
				cookieValue := keyvalue.CookieValue{
					Cookie: newProfile.Spec.BinaryIDFromPath(
						binaryPaths[index],
					),
				}
				keyPtr, err := key.GetUnsafePointer(byteOrder)
				if err != nil {
					return err
				}
				valuePtr, err := cookieValue.GetUnsafePointer(byteOrder)
				if err != nil {
					return err
				}
				// update the value with the new cookie
				if err := pidBinaryIDsMap.Put(keyPtr, valuePtr); err != nil {
					return err
				}
			}
		}
		if updateDone {
			return nil
		}
		time.Sleep(1 * time.Second)
	}
	profileLoaderLogger.Errorln("couldn't flush pid_binary_id of old binary_ids")
	return nil
}

func (pl *ProfileLoader) deletePidBinaryID(oldBinaryIDs []keyvalue.Cookie, newProfile *v1.SecurityProfile) error {
	byteOrder := utils.GetHostByteOrder()
	pidBinaryIDsMap, ok := pl.collection.Maps["pid_binary_id"]
	if !ok {
		return errors.New("couldn't find pid_binary_id")
	}
	for i := 0; i < 10; i++ {
		updateDone := true
		// loop through the pid <-> binary_id and look for old binary_id cookies
		iterator := pidBinaryIDsMap.Iterate()
		var key keyvalue.PIDKey
		var value keyvalue.CookieValue
		for iterator.Next(&key, &value) {
			if index := keyvalue.CookieListContains(oldBinaryIDs, value.Cookie); index >= 0 {
				updateDone = false
				keyPtr, err := key.GetUnsafePointer(byteOrder)
				if err != nil {
					return err
				}
				// delete the binding
				if err := pidBinaryIDsMap.Delete(keyPtr); err != nil {
					return err
				}
			}
		}
		if updateDone {
			return nil
		}
		time.Sleep(1 * time.Second)
	}
	profileLoaderLogger.Errorln("couldn't flush pid_binary_id of old binary_ids")
	return nil
}
