package model

// ProcessorName - Processor Name
type ProcessorName string

var (
	// TracerProcessor - Console tracer processor
	TracerProcessor ProcessorName = "Tracer"
	// DogTracerProcessor - Datadog Tracer processor
	DogTracerProcessor ProcessorName = "DogTracer"
	// ProfilerProcessor - Profiler processor
	ProfilerProcessor ProcessorName = "Profiler"
	// ProfileLoaderProcessor - SecurityProfile processor
	ProfileLoaderProcessor ProcessorName = "ProfileLoader"
)

// Processor - Defines the Processor interface
type Processor interface {
	Start(nsp NSPInterface) error
	Stop() error
	GetEventChan() chan ProbeEvent
	GetName() ProcessorName
}
