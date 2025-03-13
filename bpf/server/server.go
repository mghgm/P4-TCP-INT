package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/cilium/ebpf"
)

func main() {
	mapID := ebpf.MapID(5)

	bpfMap, err := ebpf.NewMapFromID(mapID)
	if err != nil {
		log.Fatalf("Failed to open BPF map by ID: %v", err)
	}
	defer bpfMap.Close()

	var key [6]byte
	var value [12]byte

	iter := bpfMap.Iterate()
	for iter.Next(&key, &value) {
		fmt.Printf("Key: %s, Value: %s\n", hex.EncodeToString(key[:]), hex.EncodeToString(value[:]))
	}

	if err := iter.Err(); err != nil {
		log.Fatalf("Error iterating over BPF map: %v", err)
	}
}
