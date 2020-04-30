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
