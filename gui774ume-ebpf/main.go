package main

import (
	"fmt"
	"os"
	"os/signal"
	"github.com/Gui774ume/ebpf"
)

const ebpfBytecode = "probe.o"

func main() {
	coll, err := ebpf.LoadCollection(ebpfBytecode)
	if err != nil {
		panic(err)
	}
	if err := coll.EnableKprobes(-1); err != nil {
		panic(err)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)
	<-sig

	if errs := coll.Close(); len(errs) > 0 {
		fmt.Println(err)
	}
}
