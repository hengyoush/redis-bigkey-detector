// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64

package bpf

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type AgentBigkeyLog struct {
	BigkeyArgs [16]struct {
		Type     uint32
		Encoding uint32
		Arg0     [160]int8
		Trucated bool
		_        [3]byte
		Len      int32
	}
	Fd     uint32
	ArgLen int32
}

// LoadAgent returns the embedded CollectionSpec for Agent.
func LoadAgent() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_AgentBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load Agent: %w", err)
	}

	return spec, err
}

// LoadAgentObjects loads Agent and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*AgentObjects
//	*AgentPrograms
//	*AgentMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func LoadAgentObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := LoadAgent()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// AgentSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type AgentSpecs struct {
	AgentProgramSpecs
	AgentMapSpecs
}

// AgentSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type AgentProgramSpecs struct {
	AddReplyToBufferOrList *ebpf.ProgramSpec `ebpf:"addReplyToBufferOrList"`
	CallEntry              *ebpf.ProgramSpec `ebpf:"callEntry"`
	CallReturn             *ebpf.ProgramSpec `ebpf:"callReturn"`
}

// AgentMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type AgentMapSpecs struct {
	BigkeyEventMap    *ebpf.MapSpec `ebpf:"bigkey_event_map"`
	BigkeyLogStackMap *ebpf.MapSpec `ebpf:"bigkey_log_stack_map"`
	CallArgsMap       *ebpf.MapSpec `ebpf:"call_args_map"`
	ReplyBytesMap     *ebpf.MapSpec `ebpf:"reply_bytes_map"`
}

// AgentObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to LoadAgentObjects or ebpf.CollectionSpec.LoadAndAssign.
type AgentObjects struct {
	AgentPrograms
	AgentMaps
}

func (o *AgentObjects) Close() error {
	return _AgentClose(
		&o.AgentPrograms,
		&o.AgentMaps,
	)
}

// AgentMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to LoadAgentObjects or ebpf.CollectionSpec.LoadAndAssign.
type AgentMaps struct {
	BigkeyEventMap    *ebpf.Map `ebpf:"bigkey_event_map"`
	BigkeyLogStackMap *ebpf.Map `ebpf:"bigkey_log_stack_map"`
	CallArgsMap       *ebpf.Map `ebpf:"call_args_map"`
	ReplyBytesMap     *ebpf.Map `ebpf:"reply_bytes_map"`
}

func (m *AgentMaps) Close() error {
	return _AgentClose(
		m.BigkeyEventMap,
		m.BigkeyLogStackMap,
		m.CallArgsMap,
		m.ReplyBytesMap,
	)
}

// AgentPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to LoadAgentObjects or ebpf.CollectionSpec.LoadAndAssign.
type AgentPrograms struct {
	AddReplyToBufferOrList *ebpf.Program `ebpf:"addReplyToBufferOrList"`
	CallEntry              *ebpf.Program `ebpf:"callEntry"`
	CallReturn             *ebpf.Program `ebpf:"callReturn"`
}

func (p *AgentPrograms) Close() error {
	return _AgentClose(
		p.AddReplyToBufferOrList,
		p.CallEntry,
		p.CallReturn,
	)
}

func _AgentClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed agent_x86_bpfel.o
var _AgentBytes []byte
