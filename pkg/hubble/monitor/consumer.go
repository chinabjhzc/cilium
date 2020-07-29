// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package monitor

import (
	"time"

	"github.com/cilium/cilium/pkg/hubble/observer"
	observerTypes "github.com/cilium/cilium/pkg/hubble/observer/types"
	"github.com/cilium/cilium/pkg/monitor/agent/consumer"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

type hubbleConsumer struct {
	observer      observer.GRPCServer
	numEventsLost uint64
}

// NewHubbleConsumer returns an initialized pointer to hubbleConsumer.
func NewHubbleConsumer(observer observer.GRPCServer) consumer.MonitorConsumer {
	mc := &hubbleConsumer{
		observer:      observer,
		numEventsLost: 0,
	}
	return mc
}

func (mc *hubbleConsumer) sendEventQueueLostEvents() {
	lostEvent := &observerTypes.MonitorEvent{
		Timestamp: time.Now(),
		NodeName:  nodeTypes.GetName(),
		Payload: &observerTypes.LostEvent{
			Source:        observerTypes.LostEventSourceEventsQueue,
			NumLostEvents: mc.numEventsLost,
		},
	}
	select {
	case mc.observer.GetEventsChannel() <- lostEvent:
		mc.numEventsLost = 0
	default:
	}
}

func (mc *hubbleConsumer) sendEvent(event *observerTypes.MonitorEvent) {
	if mc.numEventsLost > 0 {
		mc.sendEventQueueLostEvents()
	}

	select {
	case mc.observer.GetEventsChannel() <- event:
	default:
		mc.observer.GetLogger().Debug("hubble events queue is full, dropping message")
		mc.numEventsLost++
	}
}

func (mc *hubbleConsumer) NotifyAgentEvent(typ int, message interface{}) {
	mc.sendEvent(&observerTypes.MonitorEvent{
		Timestamp: time.Now(),
		NodeName:  nodeTypes.GetName(),
		Payload: &observerTypes.AgentEvent{
			Type:    typ,
			Message: message,
		},
	})
}

func (mc *hubbleConsumer) NotifyPerfEvent(data []byte, cpu int) {
	mc.sendEvent(&observerTypes.MonitorEvent{
		Timestamp: time.Now(),
		NodeName:  nodeTypes.GetName(),
		Payload: &observerTypes.PerfEvent{
			Data: data,
			CPU:  cpu,
		},
	})
}

func (mc *hubbleConsumer) NotifyPerfEventLost(numLostEvents uint64, cpu int) {
	mc.sendEvent(&observerTypes.MonitorEvent{
		Timestamp: time.Now(),
		NodeName:  nodeTypes.GetName(),
		Payload: &observerTypes.LostEvent{
			Source:        observerTypes.LostEventSourcePerfRingBuffer,
			NumLostEvents: numLostEvents,
			CPU:           cpu,
		},
	})
}

// Close is a no-op for hubbleConsumer.
func (mc *hubbleConsumer) Close() {}
