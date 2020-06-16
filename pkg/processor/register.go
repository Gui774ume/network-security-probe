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
package processor

import (
	"github.com/Gui774ume/network-security-probe/pkg/config"
	"github.com/Gui774ume/network-security-probe/pkg/model"
	"github.com/Gui774ume/network-security-probe/pkg/processor/profileloader"
)

// Instances of the different processors
var logTracer = Tracer{}
var dogTracer = DogTracer{}
var profileLoader = profileloader.ProfileLoader{}

// ProcessorsList - List of all the processors
var ProcessorsList = []model.Processor{
	&logTracer,
	&dogTracer,
	&profileLoader,
}

// RegisterProcessors - Register processors
func RegisterProcessors(config *config.NSPConfig) map[model.EventType][]model.Processor {
	return map[model.EventType][]model.Processor{
		model.AnyEventType: []model.Processor{
			// &logTracer,
			// &dogTracer,
		},
		model.ContainerRunningEventType: []model.Processor{
			// &logTracer,
			// &dogTracer,
			&profileLoader,
		},
		model.ContainerExitedEventType: []model.Processor{
			// &logTracer,
			// &dogTracer,
			&profileLoader,
		},
		model.SecurityProfileCreatedType: []model.Processor{
			// &logTracer,
			// &dogTracer,
			&profileLoader,
		},
		model.SecurityProfileUpdatedType: []model.Processor{
			// &logTracer,
			// &dogTracer,
			&profileLoader,
		},
		model.SecurityProfileDeletedType: []model.Processor{
			// &logTracer,
			// &dogTracer,
			&profileLoader,
		},
		model.NetworkAlertType: []model.Processor{
			&logTracer,
			&dogTracer,
		},
		model.DNSQueryType: []model.Processor{
			&logTracer,
			&dogTracer,
		},
		model.DNSResponseType: []model.Processor{
			&logTracer,
			&dogTracer,
		},
	}
}
