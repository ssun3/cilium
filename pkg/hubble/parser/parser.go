// Copyright 2019 Authors of Hubble
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

package parser

import (
	"time"

	pb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	observerTypes "github.com/cilium/cilium/pkg/hubble/observer/types"
	"github.com/cilium/cilium/pkg/hubble/parser/errors"
	"github.com/cilium/cilium/pkg/hubble/parser/getters"
	"github.com/cilium/cilium/pkg/hubble/parser/options"
	"github.com/cilium/cilium/pkg/hubble/parser/seven"
	"github.com/cilium/cilium/pkg/hubble/parser/threefour"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	"github.com/golang/protobuf/ptypes"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/sirupsen/logrus"
)

// Parser for all flows
type Parser struct {
	l34 *threefour.Parser
	l7  *seven.Parser
}

// New creates a new parser
func New(
	log logrus.FieldLogger,
	endpointGetter getters.EndpointGetter,
	identityGetter getters.IdentityGetter,
	dnsGetter getters.DNSGetter,
	ipGetter getters.IPGetter,
	serviceGetter getters.ServiceGetter,
	opts ...options.Option,
) (*Parser, error) {

	l34, err := threefour.New(log, endpointGetter, identityGetter, dnsGetter, ipGetter, serviceGetter)
	if err != nil {
		return nil, err
	}

	l7, err := seven.New(log, dnsGetter, ipGetter, serviceGetter, opts...)
	if err != nil {
		return nil, err
	}

	return &Parser{
		l34: l34,
		l7:  l7,
	}, nil
}

func lostEventSourceToProto(source int) pb.LostEventSource {
	switch source {
	case observerTypes.LostEventSourcePerfRingBuffer:
		return pb.LostEventSource_PERF_EVENT_RING_BUFFER
	case observerTypes.LostEventSourceEventsQueue:
		return pb.LostEventSource_OBSERVER_EVENTS_QUEUE
	default:
		return pb.LostEventSource_UNKNOWN_LOST_EVENT_SOURCE
	}
}

func agentNotifyTimeNotificationToProto(typ pb.AgentEventType, msg monitorAPI.AgentNotifyMessage) *pb.AgentEvent {
	var ts *timestamppb.Timestamp
	if notification, ok := msg.Notification.(monitorAPI.TimeNotification); ok {
		if goTime, err := time.Parse(time.RFC3339Nano, notification.Time); err == nil {
			ts, _ = ptypes.TimestampProto(goTime)
		}
	}
	return &pb.AgentEvent{
		Type: typ,
		Notification: &pb.AgentEvent_Start{
			Start: &pb.TimeNotification{
				Time: ts,
			},
		},
	}
}

func agentNotifyPolicyNotificationToProto(typ pb.AgentEventType, msg monitorAPI.AgentNotifyMessage) *pb.AgentEvent {
	var ruleCount int
	var revision uint64
	var labels []string
	if n, ok := msg.Notification.(monitorAPI.PolicyUpdateNotification); ok {
		ruleCount = n.RuleCount
		labels = n.Labels
		revision = n.Revision
	}

	return &pb.AgentEvent{
		Type: typ,
		Notification: &pb.AgentEvent_PolicyUpdate{
			PolicyUpdate: &pb.PolicyUpdateNotification{
				RuleCount: int64(ruleCount),
				Labels:    labels,
				Revision:  revision,
			},
		},
	}
}

func agentNotifyEndpointRegenNotificationToProto(typ pb.AgentEventType, msg monitorAPI.AgentNotifyMessage) *pb.AgentEvent {
	var id uint64
	var labels []string
	var e string
	if n, ok := msg.Notification.(monitorAPI.EndpointRegenNotification); ok {
		id = n.ID
		labels = n.Labels
		e = n.Error
	}

	return &pb.AgentEvent{
		Type: typ,
		Notification: &pb.AgentEvent_EndpointRegenerate{
			EndpointRegenerate: &pb.EndpointRegenNotification{
				Id:     id,
				Labels: labels,
				Error:  e,
			},
		},
	}
}

func agentNotifyEndpointUpdateNotificationToProto(typ pb.AgentEventType, msg monitorAPI.AgentNotifyMessage) *pb.AgentEvent {
	var id uint64
	var labels []string
	var e, podName, namespace string
	if n, ok := msg.Notification.(monitorAPI.EndpointNotification); ok {
		id = n.ID
		labels = n.Labels
		e = n.Error
		podName = n.PodName
		namespace = n.Namespace
	}

	return &pb.AgentEvent{
		Type: typ,
		Notification: &pb.AgentEvent_EndpointUpdate{
			EndpointUpdate: &pb.EndpointUpdateNotification{
				Id:        id,
				Labels:    labels,
				Error:     e,
				PodName:   podName,
				Namespace: namespace,
			},
		},
	}
}
func agentNotifyIPCacheNotificationToProto(typ pb.AgentEventType, msg monitorAPI.AgentNotifyMessage) *pb.AgentEvent {
	var cidr string
	var identity uint32
	var oldIdentity *wrapperspb.UInt32Value
	var hostIPString, oldHostIPString string
	var encryptKey uint8
	var namespace, podName string
	if n, ok := msg.Notification.(monitorAPI.IPCacheNotification); ok {
		cidr = n.CIDR
		identity = n.Identity
		if n.OldIdentity != nil {
			oldIdentity = &wrapperspb.UInt32Value{
				Value: *n.OldIdentity,
			}
		}
		if n.HostIP != nil {
			hostIPString = n.HostIP.String()
		}
		if n.OldHostIP != nil {
			oldHostIPString = n.OldHostIP.String()
		}
		encryptKey = n.EncryptKey
		namespace = n.Namespace
		podName = n.PodName
	}
	return &pb.AgentEvent{
		Type: typ,
		Notification: &pb.AgentEvent_IpcacheUpdate{
			IpcacheUpdate: &pb.IPCacheNotification{
				Cidr:        cidr,
				Identity:    identity,
				OldIdentity: oldIdentity,
				HostIp:      hostIPString,
				OldHostIp:   oldHostIPString,
				EncryptKey:  uint32(encryptKey),
				Namespace:   namespace,
				PodName:     podName,
			},
		},
	}
}

func agentNotifyServiceUpsertedToProto(typ pb.AgentEventType, msg monitorAPI.AgentNotifyMessage) *pb.AgentEvent {
	var id uint32
	var feAddr *pb.ServiceUpsertNotificationAddr
	var beAddrs []*pb.ServiceUpsertNotificationAddr
	var svcType, svcTrafficPolicy, svcName, svcNamespace string
	if n, ok := msg.Notification.(monitorAPI.ServiceUpsertNotification); ok {
		id = n.ID
		feAddr = &pb.ServiceUpsertNotificationAddr{
			Ip:   n.Frontend.IP.String(),
			Port: uint32(n.Frontend.Port),
		}
		for _, be := range n.Backends {
			var ipStr string
			if be.IP != nil {
				ipStr = be.IP.String()
			}
			beAddrs = append(beAddrs, &pb.ServiceUpsertNotificationAddr{
				Ip:   ipStr,
				Port: uint32(be.Port),
			})
		}
		svcType = n.Type
		svcTrafficPolicy = n.TrafficPolicy
		svcName = n.Name
		svcNamespace = n.Namespace
	}
	return &pb.AgentEvent{
		Type: typ,
		Notification: &pb.AgentEvent_ServiceUpserted{
			ServiceUpserted: &pb.ServiceUpsertNotification{
				Id:               id,
				FrontendAddress:  feAddr,
				BackendAddresses: beAddrs,
				Type:             svcType,
				TrafficPolicy:    svcTrafficPolicy,
				Name:             svcName,
				Namespace:        svcNamespace,
			},
		},
	}
}

func agentNotifyServiceDeletedToProto(typ pb.AgentEventType, msg monitorAPI.AgentNotifyMessage) *pb.AgentEvent {
	var id uint32
	if n, ok := msg.Notification.(monitorAPI.ServiceDeleteNotification); ok {
		id = n.ID
	}
	return &pb.AgentEvent{
		Type: typ,
		Notification: &pb.AgentEvent_ServiceDeleted{
			ServiceDeleted: &pb.ServiceDeleteNotification{
				Id: id,
			},
		},
	}
}

func agentNotifyMessageToProto(msg monitorAPI.AgentNotifyMessage) *pb.AgentEvent {
	switch msg.Type {
	case monitorAPI.AgentNotifyStart:
		return agentNotifyTimeNotificationToProto(pb.AgentEventType_START, msg)
	case monitorAPI.AgentNotifyPolicyUpdated:
		return agentNotifyPolicyNotificationToProto(pb.AgentEventType_POLICY_UPDATED, msg)
	case monitorAPI.AgentNotifyPolicyDeleted:
		return agentNotifyPolicyNotificationToProto(pb.AgentEventType_POLICY_DELETED, msg)
	case monitorAPI.AgentNotifyEndpointRegenerateSuccess:
		return agentNotifyEndpointRegenNotificationToProto(pb.AgentEventType_ENDPOINT_REGENERATE_SUCCESS, msg)
	case monitorAPI.AgentNotifyEndpointRegenerateFail:
		return agentNotifyEndpointRegenNotificationToProto(pb.AgentEventType_ENDPOINT_REGENERATE_FAIL, msg)
	case monitorAPI.AgentNotifyEndpointCreated:
		return agentNotifyEndpointUpdateNotificationToProto(pb.AgentEventType_ENDPOINT_CREATED, msg)
	case monitorAPI.AgentNotifyEndpointDeleted:
		return agentNotifyEndpointUpdateNotificationToProto(pb.AgentEventType_ENDPOINT_DELETED, msg)
	case monitorAPI.AgentNotifyIPCacheUpserted:
		return agentNotifyIPCacheNotificationToProto(pb.AgentEventType_IPCACHE_UPSERTED, msg)
	case monitorAPI.AgentNotifyIPCacheDeleted:
		return agentNotifyIPCacheNotificationToProto(pb.AgentEventType_IPCACHE_DELETED, msg)
	case monitorAPI.AgentNotifyServiceUpserted:
		return agentNotifyServiceUpsertedToProto(pb.AgentEventType_SERVICE_UPSERTED, msg)
	case monitorAPI.AgentNotifyServiceDeleted:
		return agentNotifyServiceDeletedToProto(pb.AgentEventType_SERVICE_DELETED, msg)
	default:
		return &pb.AgentEvent{
			Type: pb.AgentEventType_UNSPECIFIED,
		}
	}
}

// Decode decodes a cilium monitor 'payload' and returns a v1.Event with
// the Event field populated.
func (p *Parser) Decode(monitorEvent *observerTypes.MonitorEvent) (*v1.Event, error) {
	if monitorEvent == nil {
		return nil, errors.ErrEmptyData
	}

	// TODO: Pool decoded flows instead of allocating new objects each time.
	ts, _ := ptypes.TimestampProto(monitorEvent.Timestamp)
	ev := &v1.Event{
		Timestamp: ts,
	}

	switch payload := monitorEvent.Payload.(type) {
	case *observerTypes.PerfEvent:
		flow := &pb.Flow{}
		if err := p.l34.Decode(payload.Data, flow); err != nil {
			return nil, err
		}
		// FIXME: Time and NodeName are now part of GetFlowsResponse. We
		// populate these fields for compatibility with old clients.
		flow.Time = ts
		flow.NodeName = monitorEvent.NodeName
		ev.Event = flow
		return ev, nil
	case *observerTypes.AgentEvent:
		switch payload.Type {
		case monitorAPI.MessageTypeAccessLog:
			flow := &pb.Flow{}
			logrecord, ok := payload.Message.(accesslog.LogRecord)
			if !ok {
				return nil, errors.ErrInvalidAgentMessageType
			}
			if err := p.l7.Decode(&logrecord, flow); err != nil {
				return nil, err
			}
			// FIXME: Time and NodeName are now part of GetFlowsResponse. We
			// populate these fields for compatibility with old clients.
			flow.Time = ts
			flow.NodeName = monitorEvent.NodeName
			ev.Event = flow
			return ev, nil
		case monitorAPI.MessageTypeAgent:
			agentNotifyMessage, ok := payload.Message.(monitorAPI.AgentNotifyMessage)
			if !ok {
				return nil, errors.ErrInvalidAgentMessageType
			}
			ev.Event = agentNotifyMessageToProto(agentNotifyMessage)
			return ev, nil
		default:
			return nil, errors.ErrUnknownEventType
		}
	case *observerTypes.LostEvent:
		ev.Event = &pb.LostEvent{
			Source:        lostEventSourceToProto(payload.Source),
			NumEventsLost: payload.NumLostEvents,
			Cpu: &wrappers.Int32Value{
				Value: int32(payload.CPU),
			},
		}
		return ev, nil
	case nil:
		return ev, errors.ErrEmptyData
	default:
		return nil, errors.ErrUnknownEventType
	}
}
