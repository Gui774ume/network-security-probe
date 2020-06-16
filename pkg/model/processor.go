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
