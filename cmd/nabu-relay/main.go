package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/nabu-tunnel/nabu/pkg/version"
)

func main() {
	ver := flag.Bool("version", false, "Sürüm bilgisini göster")
	flag.Parse()

	if *ver {
		fmt.Printf("nabu-relay %s (built %s)\n", version.Version, version.BuildTime)
		os.Exit(0)
	}

	fmt.Println("nabu-relay başlıyor... (henüz implement edilmedi)")
}
