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

// +build !privileged_tests

package parser

import (
	stderrors "errors"
	"io/ioutil"
	"net"
	"testing"
	"time"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	observerTypes "github.com/cilium/cilium/pkg/hubble/observer/types"
	"github.com/cilium/cilium/pkg/hubble/parser/errors"
	"github.com/cilium/cilium/pkg/hubble/testutils"
	"github.com/cilium/cilium/pkg/monitor"
	"github.com/cilium/cilium/pkg/monitor/api"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

var log *logrus.Logger

func init() {
	log = logrus.New()
	log.SetOutput(ioutil.Discard)
}

func Test_InvalidPayloads(t *testing.T) {
	p, err := New(log, nil, nil, nil, nil, nil)
	assert.NoError(t, err)

	_, err = p.Decode(nil)
	assert.Equal(t, err, errors.ErrEmptyData)

	_, err = p.Decode(&observerTypes.MonitorEvent{
		Payload: nil,
	})
	assert.Equal(t, err, errors.ErrEmptyData)

	_, err = p.Decode(&observerTypes.MonitorEvent{
		Payload: &observerTypes.PerfEvent{
			Data: []byte{100},
		},
	})
	assert.Equal(t, err, errors.NewErrInvalidType(100))

	_, err = p.Decode(&observerTypes.MonitorEvent{
		Payload: "not valid",
	})
	assert.Equal(t, err, errors.ErrUnknownEventType)
}

func Test_ParserDispatch(t *testing.T) {
	p, err := New(log, nil, nil, nil, nil, nil)
	assert.NoError(t, err)

	// Test L3/L4 record
	tn := monitor.TraceNotifyV0{
		Type: byte(api.MessageTypeTrace),
	}
	data, err := testutils.CreateL3L4Payload(tn)
	assert.NoError(t, err)

	e, err := p.Decode(&observerTypes.MonitorEvent{
		Payload: &observerTypes.PerfEvent{
			Data: data,
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, flowpb.FlowType_L3_L4, e.GetFlow().GetType())

	// Test L7 dispatch
	node := "k8s1"
	e, err = p.Decode(&observerTypes.MonitorEvent{
		NodeName: node,
		Payload: &observerTypes.AgentEvent{
			Type: api.MessageTypeAccessLog,
			Message: accesslog.LogRecord{
				Timestamp: "2006-01-02T15:04:05.999999999Z",
			},
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, node, e.GetFlow().GetNodeName())
	assert.Equal(t, flowpb.FlowType_L7, e.GetFlow().GetType())
}

func Test_EventType_RecordLost(t *testing.T) {
	p, err := New(log, nil, nil, nil, nil, nil)
	assert.NoError(t, err)

	ts := time.Now()
	ev, err := p.Decode(&observerTypes.MonitorEvent{
		Timestamp: ts,
		Payload: &observerTypes.LostEvent{
			Source:        observerTypes.LostEventSourcePerfRingBuffer,
			NumLostEvents: 1001,
			CPU:           3,
		},
	})
	assert.NoError(t, err)

	protoTimestamp, err := ptypes.TimestampProto(ts)
	assert.NoError(t, err)
	assert.Equal(t, &v1.Event{
		Timestamp: protoTimestamp,
		Event: &flowpb.LostEvent{
			NumEventsLost: 1001,
			Cpu:           &wrappers.Int32Value{Value: 3},
			Source:        flowpb.LostEventSource_PERF_EVENT_RING_BUFFER,
		},
	}, ev)
}

type mockEndpoint struct {
	ID        uint64
	Labels    []string
	PodName   string
	Namespace string
}

func (e *mockEndpoint) GetID() uint64           { return e.ID }
func (e *mockEndpoint) GetOpLabels() []string   { return e.Labels }
func (e *mockEndpoint) GetK8sPodName() string   { return e.PodName }
func (e *mockEndpoint) GetK8sNamespace() string { return e.Namespace }

func TestDecodeAgentEvent(t *testing.T) {
	p, err := New(log, nil, nil, nil, nil, nil)
	assert.NoError(t, err)

	ts := time.Now()
	protoTimestamp, err := ptypes.TimestampProto(ts)
	assert.NoError(t, err)

	agentStartTS := ts.Add(-10 * time.Minute)
	protoAgentStartTimestamp, err := ptypes.TimestampProto(agentStartTS)
	assert.NoError(t, err)

	mockEP := &mockEndpoint{
		ID:        65535,
		Labels:    []string{"custom=label", "label=another"},
		PodName:   "devnull",
		Namespace: "hubble",
	}

	oldID := uint32(511)

	tt := []struct {
		name string
		msg  api.AgentNotifyMessage
		ev   *v1.Event
	}{
		{
			name: "empty AgentNotifyMessage",
			msg:  api.AgentNotifyMessage{},
			ev: &v1.Event{
				Timestamp: protoTimestamp,
				Event:     &flowpb.AgentEvent{},
			},
		},
		{
			name: "unspecified AgentNotifyMessage",
			msg: api.AgentNotifyMessage{
				Type: api.AgentNotifyUnspec,
				Notification: struct {
					foo int64
					bar int32
				}{
					foo: 23,
					bar: 42,
				},
			},
			ev: &v1.Event{
				Timestamp: protoTimestamp,
				Event:     &flowpb.AgentEvent{},
			},
		},
		{
			name: "StartMessage",
			msg:  api.StartMessage(agentStartTS),
			ev: &v1.Event{
				Timestamp: protoTimestamp,
				Event: &flowpb.AgentEvent{
					Type: flowpb.AgentEventType_START,
					Notification: &flowpb.AgentEvent_Start{
						Start: &flowpb.TimeNotification{
							Time: protoAgentStartTimestamp,
						},
					},
				},
			},
		},
		{
			name: "PolicyUpdateMessage",
			msg:  api.PolicyUpdateMessage(42, []string{"hubble=rocks", "cilium=too"}, 7),
			ev: &v1.Event{
				Timestamp: protoTimestamp,
				Event: &flowpb.AgentEvent{
					Type: flowpb.AgentEventType_POLICY_UPDATED,
					Notification: &flowpb.AgentEvent_PolicyUpdate{
						PolicyUpdate: &flowpb.PolicyUpdateNotification{
							RuleCount: 42,
							Labels:    []string{"hubble=rocks", "cilium=too"},
							Revision:  7,
						},
					},
				},
			},
		},
		{
			name: "PolicyDeleteMessage",
			msg:  api.PolicyDeleteMessage(23, []string{"foo=bar"}, 255),
			ev: &v1.Event{
				Timestamp: protoTimestamp,
				Event: &flowpb.AgentEvent{
					Type: flowpb.AgentEventType_POLICY_DELETED,
					Notification: &flowpb.AgentEvent_PolicyUpdate{
						PolicyUpdate: &flowpb.PolicyUpdateNotification{
							RuleCount: 23,
							Labels:    []string{"foo=bar"},
							Revision:  255,
						},
					},
				},
			},
		},
		{
			name: "EndpointRegenMessage success",
			msg:  api.EndpointRegenMessage(mockEP, nil),
			ev: &v1.Event{
				Timestamp: protoTimestamp,
				Event: &flowpb.AgentEvent{
					Type: flowpb.AgentEventType_ENDPOINT_REGENERATE_SUCCESS,
					Notification: &flowpb.AgentEvent_EndpointRegenerate{
						EndpointRegenerate: &flowpb.EndpointRegenNotification{
							Id:     mockEP.GetID(),
							Labels: mockEP.GetOpLabels(),
							Error:  "",
						},
					},
				},
			},
		},
		{
			name: "EndpointRegenMessage fail",
			msg:  api.EndpointRegenMessage(mockEP, stderrors.New("error regenerating endpoint")),
			ev: &v1.Event{
				Timestamp: protoTimestamp,
				Event: &flowpb.AgentEvent{
					Type: flowpb.AgentEventType_ENDPOINT_REGENERATE_FAIL,
					Notification: &flowpb.AgentEvent_EndpointRegenerate{
						EndpointRegenerate: &flowpb.EndpointRegenNotification{
							Id:     mockEP.GetID(),
							Labels: mockEP.GetOpLabels(),
							Error:  "error regenerating endpoint",
						},
					},
				},
			},
		},
		{
			name: "EndpointCreateMessage",
			msg:  api.EndpointCreateMessage(mockEP),
			ev: &v1.Event{
				Timestamp: protoTimestamp,
				Event: &flowpb.AgentEvent{
					Type: flowpb.AgentEventType_ENDPOINT_CREATED,
					Notification: &flowpb.AgentEvent_EndpointUpdate{
						EndpointUpdate: &flowpb.EndpointUpdateNotification{
							Id:        mockEP.GetID(),
							Labels:    mockEP.GetOpLabels(),
							Error:     "",
							PodName:   mockEP.GetK8sPodName(),
							Namespace: mockEP.GetK8sNamespace(),
						},
					},
				},
			},
		},
		{
			name: "EndpointDeleteMessage",
			msg:  api.EndpointDeleteMessage(mockEP),
			ev: &v1.Event{
				Timestamp: protoTimestamp,
				Event: &flowpb.AgentEvent{
					Type: flowpb.AgentEventType_ENDPOINT_DELETED,
					Notification: &flowpb.AgentEvent_EndpointUpdate{
						EndpointUpdate: &flowpb.EndpointUpdateNotification{
							Id:        mockEP.GetID(),
							Labels:    mockEP.GetOpLabels(),
							Error:     "",
							PodName:   mockEP.GetK8sPodName(),
							Namespace: mockEP.GetK8sNamespace(),
						},
					},
				},
			},
		},
		{
			name: "IPCacheUpsertedMessage (insert)",
			msg:  api.IPCacheUpsertedMessage("10.0.1.42/32", 1023, nil, net.ParseIP("10.1.5.4"), nil, 0xff, "default", "foobar"),
			ev: &v1.Event{
				Timestamp: protoTimestamp,
				Event: &flowpb.AgentEvent{
					Type: flowpb.AgentEventType_IPCACHE_UPSERTED,
					Notification: &flowpb.AgentEvent_IpcacheUpdate{
						IpcacheUpdate: &flowpb.IPCacheNotification{
							Cidr:        "10.0.1.42/32",
							Identity:    1023,
							OldIdentity: nil,
							HostIp:      "10.1.5.4",
							OldHostIp:   "",
							EncryptKey:  0xff,
							Namespace:   "default",
							PodName:     "foobar",
						},
					},
				},
			},
		},
		{
			name: "IPCacheUpsertedMessage (update)",
			msg:  api.IPCacheUpsertedMessage("192.168.10.11/32", 1023, &oldID, net.ParseIP("10.1.5.4"), net.ParseIP("10.2.6.11"), 5, "hubble", "podmcpodface"),
			ev: &v1.Event{
				Timestamp: protoTimestamp,
				Event: &flowpb.AgentEvent{
					Type: flowpb.AgentEventType_IPCACHE_UPSERTED,
					Notification: &flowpb.AgentEvent_IpcacheUpdate{
						IpcacheUpdate: &flowpb.IPCacheNotification{
							Cidr:     "192.168.10.11/32",
							Identity: 1023,
							OldIdentity: &wrapperspb.UInt32Value{
								Value: oldID,
							},
							HostIp:     "10.1.5.4",
							OldHostIp:  "10.2.6.11",
							EncryptKey: 5,
							Namespace:  "hubble",
							PodName:    "podmcpodface",
						},
					},
				},
			},
		},
		{
			name: "IPCacheDeletedMessage",
			msg:  api.IPCacheDeletedMessage("192.168.10.0/24", 6048, nil, net.ParseIP("10.1.5.4"), nil, 0, "", ""),
			ev: &v1.Event{
				Timestamp: protoTimestamp,
				Event: &flowpb.AgentEvent{
					Type: flowpb.AgentEventType_IPCACHE_DELETED,
					Notification: &flowpb.AgentEvent_IpcacheUpdate{
						IpcacheUpdate: &flowpb.IPCacheNotification{
							Cidr:        "192.168.10.0/24",
							Identity:    6048,
							OldIdentity: nil,
							HostIp:      "10.1.5.4",
							OldHostIp:   "",
							EncryptKey:  0,
							Namespace:   "",
							PodName:     "",
						},
					},
				},
			},
		},
		{
			name: "ServiceUpsertMessage",
			msg: api.ServiceUpsertMessage(
				214,
				monitorAPI.ServiceUpsertNotificationAddr{
					IP:   net.ParseIP("10.240.12.1"),
					Port: 8080,
				},
				[]monitorAPI.ServiceUpsertNotificationAddr{
					{
						IP:   net.ParseIP("192.168.3.59"),
						Port: 9099,
					},
					{
						IP:   net.ParseIP("192.168.3.57"),
						Port: 7077,
					},
				},
				"ClusterIP",
				"myTrafficPolicy",
				"myService",
				"myNamespace",
			),
			ev: &v1.Event{
				Timestamp: protoTimestamp,
				Event: &flowpb.AgentEvent{
					Type: flowpb.AgentEventType_SERVICE_UPSERTED,
					Notification: &flowpb.AgentEvent_ServiceUpserted{
						ServiceUpserted: &flowpb.ServiceUpsertNotification{
							Id: 214,
							FrontendAddress: &flowpb.ServiceUpsertNotificationAddr{
								Ip:   "10.240.12.1",
								Port: 8080,
							},
							BackendAddresses: []*flowpb.ServiceUpsertNotificationAddr{
								{
									Ip:   "192.168.3.59",
									Port: 9099,
								},
								{
									Ip:   "192.168.3.57",
									Port: 7077,
								},
							},
							Type:          "ClusterIP",
							TrafficPolicy: "myTrafficPolicy",
							Name:          "myService",
							Namespace:     "myNamespace",
						},
					},
				},
			},
		},
		{
			name: "ServiceDeleteMessage",
			msg:  api.ServiceDeleteMessage(1048575),
			ev: &v1.Event{
				Timestamp: protoTimestamp,
				Event: &flowpb.AgentEvent{
					Type: flowpb.AgentEventType_SERVICE_DELETED,
					Notification: &flowpb.AgentEvent_ServiceDeleted{
						ServiceDeleted: &flowpb.ServiceDeleteNotification{
							Id: 1048575,
						},
					},
				},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ev, err := p.Decode(&observerTypes.MonitorEvent{
				Timestamp: ts,
				Payload: &observerTypes.AgentEvent{
					Type:    monitorAPI.MessageTypeAgent,
					Message: tc.msg,
				},
			})
			assert.NoError(t, err)
			assert.Equal(t, tc.ev, ev)
		})
	}
}
