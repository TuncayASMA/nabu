// gen_json emits the embedded traffic profiles as JSON files.
// Usage: go run ./pkg/phantom/profiles/tools/gen_json/ -out pkg/phantom/profiles/
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/TuncayASMA/nabu/pkg/phantom/profiles"
)

func main() {
	outDir := flag.String("out", ".", "output directory for JSON files")
	flag.Parse()

	for _, name := range profiles.EmbeddedNames() {
		p, err := profiles.LoadEmbedded(name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "load %q: %v\n", name, err)
			os.Exit(1)
		}
		data, err := json.MarshalIndent(p, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "marshal %q: %v\n", name, err)
			os.Exit(1)
		}
		path := filepath.Join(*outDir, name+".json")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "write %q: %v\n", path, err)
			os.Exit(1)
		}
		fmt.Printf("wrote %s\n", path)
	}
}
