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
package informer

import (
	"time"

	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"

	v1 "github.com/Gui774ume/network-security-probe/pkg/k8s/apis/securityprobe.datadoghq.com/v1"
	spclientset "github.com/Gui774ume/network-security-probe/pkg/k8s/client/clientset/versioned"
	"github.com/Gui774ume/network-security-probe/pkg/k8s/client/informers/externalversions"
	informerv1 "github.com/Gui774ume/network-security-probe/pkg/k8s/client/informers/externalversions/securityprobe.datadoghq.com/v1"
	"github.com/Gui774ume/network-security-probe/pkg/model"
)

var (
	informerLogger = logrus.WithField("package", "informer")
)

// SecurityProfileInformer - Security profile informer
type SecurityProfileInformer struct {
	Nsp                    model.NSPInterface
	SecurityProbeClientSet *spclientset.Clientset
	Informer               informerv1.SecurityProfileInformer
	Stopper                chan struct{}
}

// Init - Initializes the SecurityProfile informer
func (spi *SecurityProfileInformer) Init(nsp model.NSPInterface) error {
	spi.Nsp = nsp
	var err error
	// Init stopper
	spi.Stopper = make(chan struct{})
	// Create custom CRD in k8s if it doesn't exist yet
	if err = v1.CreateSecurityProfileCRD(nsp.GetKubeConfig()); err != nil {
		return err
	}
	informerLogger.Debug("SecurityProfile CRD registered")
	// Create k8s client
	spi.SecurityProbeClientSet, err = spclientset.NewForConfig(nsp.GetKubeConfig())
	if err != nil {
		return err
	}
	// Create Informer
	factory := externalversions.NewSharedInformerFactory(spi.SecurityProbeClientSet, time.Minute)
	spi.Informer = factory.Securityprobe().V1().SecurityProfiles()
	// Setup event handlers
	spi.Informer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		// When a new pod gets created
		AddFunc: func(obj interface{}) {
			spi.onAdd(obj.(*v1.SecurityProfile))
		},
		// When a pod gets updated
		UpdateFunc: func(old interface{}, new interface{}) {
			spi.onUpdate(old.(*v1.SecurityProfile), new.(*v1.SecurityProfile))
		},
		// When a pod gets deleted
		DeleteFunc: func(obj interface{}) {
			spi.onDelete(obj.(*v1.SecurityProfile))
		},
	})
	return nil
}

// Start - Starts the SecurityProfile informer
func (spi *SecurityProfileInformer) Start() error {
	go spi.Informer.Informer().Run(spi.Stopper)
	informerLogger.Debug("SecurityProfile informer started")
	return nil
}

// Stop - Stops the SecurityProfile informer
func (spi *SecurityProfileInformer) Stop() error {
	close(spi.Stopper)
	runtime.HandleCrash()
	return nil
}

// onAdd - SecurityProfile creation handler
func (spi *SecurityProfileInformer) onAdd(sp *v1.SecurityProfile) {
	// Check if running containers are selected by this SecurityProfile
	spi.Nsp.DispatchEvent(&model.SecurityProfileCreatedEvent{
		EventBase: model.EventBase{
			EventType:        model.SecurityProfileCreatedType,
			EventMonitorName: model.SecurityProfileInformerMonitor,
			Timestamp:        time.Now(),
		},
		Profile: sp,
	})
}

// onUpdate - SecurityProfile update handler
func (spi *SecurityProfileInformer) onUpdate(old *v1.SecurityProfile, new *v1.SecurityProfile) {
	// If this SecurityProfile is used locally, update in in the kernel hashmaps
	spi.Nsp.DispatchEvent(&model.SecurityProfileUpdatedEvent{
		EventBase: model.EventBase{
			EventType:        model.SecurityProfileUpdatedType,
			EventMonitorName: model.SecurityProfileInformerMonitor,
			Timestamp:        time.Now(),
		},
		Old: old,
		New: new,
	})
}

// onDelete - SecurityProfile creation handler
func (spi *SecurityProfileInformer) onDelete(sp *v1.SecurityProfile) {
	// If this SecurityProfile is used locally, delete it from the kernel hashmaps
	spi.Nsp.DispatchEvent(&model.SecurityProfileDeletedEvent{
		EventBase: model.EventBase{
			EventType:        model.SecurityProfileDeletedType,
			EventMonitorName: model.SecurityProfileInformerMonitor,
			Timestamp:        time.Now(),
		},
		Profile: sp,
	})
}
