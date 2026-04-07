package version

// Build-time değişkenler — Makefile'dan ldflags ile inject edilir.
var (
	Version   = "dev"
	BuildTime = "unknown"
)
