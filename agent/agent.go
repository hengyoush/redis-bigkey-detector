package agent

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"redis-bigkey/bpf"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

func SetupAgent() {
	stopper := make(chan os.Signal)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	var spec *ebpf.CollectionSpec
	spec, err := bpf.LoadAgent()

	if err != nil {
		log.Fatal("load Agent error:", err)
	}
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Println("Remove memlock:", err)
	}
	objs := &bpf.AgentObjects{}
	// btfFile, err := btf.LoadSpec("/home/admin/3.10.0-957.21.3.el7.x86_64.btf")

	if err != nil {
		log.Fatal("load btf error:", err)
	}
	opts := &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: ebpf.LogLevelInstruction,
			LogSize:  100 * 1024 * 1024,
			// KernelTypes: btfFile,
		},
	}
	err = spec.LoadAndAssign(objs, opts)
	if err != nil {
		err = errors.Unwrap(errors.Unwrap(err))
		inner_err, ok := err.(*ebpf.VerifierError)
		if ok {
			inner_err.Truncated = false
			log.Fatalf("loadAgentObjects: %+v", inner_err)
		} else {
			log.Fatalf("loadAgentObjects: %+v", err)
		}
		return
	}
	ex, err := link.OpenExecutable("/root/workspace/redis-6.2.13/src/redis-server")
	if err != nil {
		log.Fatalln(err)
	}
	link1, err := ex.Uprobe("_addReplyToBufferOrList", objs.AddReplyToBufferOrList, nil)
	if err != nil {
		log.Fatalln(err)
	}
	defer link1.Close()
	link2, err := ex.Uprobe("call", objs.CallEntry, nil)
	if err != nil {
		log.Fatalln(err)
	}
	defer link2.Close()
	link3, err := ex.Uretprobe("call", objs.CallReturn, nil)
	if err != nil {
		log.Fatalln(err)
	}
	defer link3.Close()
	stop := false
	go func() {
		<-stopper
		stop = true
	}()

	reader, err := perf.NewReader(objs.BigkeyEventMap, 1024*1024)
	if err != nil {
		log.Fatalln(err)
	}
	go func() {
		for {
			record, err := reader.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					log.Print("[dataReader] Received signal, exiting..")
					return
				}
				log.Printf("[dataReader] reading from reader: %s\n", err)
				continue
			}
			if err := handleEvent(record.RawSample); err != nil {
				log.Printf("[dataReader] handleKernEvt err: %s\n", err)
				continue
			} else if record.LostSamples > 0 {
				log.Printf("[dataReader] lost sample: %d", record.LostSamples)
			}
		}
	}()

	log.Println("Waiting for events")

	for !stop {
		time.Sleep(time.Second * 1)
	}
	log.Println("Redis-bigkey Stopped")
	return
}

const (
	encoding_raw    = 0
	encoding_int    = 1
	encoding_embstr = 8
)

func handleEvent(record []byte) error {
	event := bpf.AgentBigkeyLog{}
	err := binary.Read(bytes.NewBuffer(record), binary.LittleEndian, &event)
	if err != nil {
		return err
	}
	log.Printf("record arglen: %d", event.ArgLen)
	for i := 0; i < int(event.ArgLen); i++ {
		each := event.BigkeyArgs[i]
		fmt.Printf("each.Len: %v\n", each.Len)
		fmt.Printf("each.Type: %v\n", each.Type)
		fmt.Printf("each.Arg0: %v\n", each.Arg0)
		fmt.Printf("each.Encoding: %v\n", each.Encoding)

		if each.Encoding == encoding_raw || each.Encoding == encoding_embstr {
			argBytes := each.Arg0[0:each.Len]
			argBytes = append(argBytes, 0)
			argStr := Int8ToStr(argBytes)
			fmt.Printf("argStr: %v\n", argStr)
		}
	}
	return nil
}

func Int8ToStr(arr []int8) string {
	str := ""
	for _, v := range arr {
		if v >= 0 && v <= 127 { // 确保int8值在有效的ASCII范围内
			str += string(byte(v)) // 将int8转换为byte并转换为字符串片段
		} else {
			// 处理可能的负数或其他非ASCII值，例如转换为rune并打印其Unicode编码
			str += fmt.Sprintf("\\u%04x", rune(v))
		}
	}
	return str
}