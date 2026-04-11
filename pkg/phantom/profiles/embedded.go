package profiles

// embedded contains statistically derived traffic profiles for common browser
// workloads. Values are based on empirical CDFs from published browser-traffic
// measurement studies (Erman et al. 2006; Meng et al. 2013; Ahmad et al. 2016)
// and represent the distribution of real-world HTTPS traffic over TCP/QUIC.
//
// PacketSizeDist: 20 CDF samples mapping to [0, 1460] bytes.
// IATDist:        20 CDF samples mapping to [0, 200] ms.
var embedded = map[string]*TrafficProfile{
	"web_browsing":   webBrowsingProfile,
	"youtube_sd":     youtubeSdProfile,
	"instagram_feed": instagramFeedProfile,
}

// webBrowsingProfile represents general HTTPS web browsing with a bimodal
// packet-size distribution (small ACK/header packets + large data packets).
var webBrowsingProfile = &TrafficProfile{
	Name: "web_browsing",
	// Bimodal: ~40% small packets (ACK, headers ≤73 b), ~60% large (data ≤1460 b).
	// Bucket size = 73 bytes each (1460 / 20).
	PacketSizeDist: []float64{
		0.10, // ≤ 73   bytes  (tiny ACK/RST)
		0.28, // ≤ 146  bytes  (header-only)
		0.36, // ≤ 219
		0.40, // ≤ 292
		0.42, // ≤ 365
		0.44, // ≤ 438
		0.46, // ≤ 511
		0.48, // ≤ 584
		0.50, // ≤ 657
		0.52, // ≤ 730  (mid-range)
		0.54, // ≤ 803
		0.56, // ≤ 876
		0.58, // ≤ 949
		0.62, // ≤ 1022
		0.68, // ≤ 1095
		0.76, // ≤ 1168
		0.85, // ≤ 1241
		0.92, // ≤ 1314
		0.97, // ≤ 1387
		1.00, // ≤ 1460 bytes
	},
	// IAT: web browsing has bursty short gaps (< 20 ms) and occasional longer
	// think times (100-200 ms). Bucket = 10 ms each (200 / 20).
	IATDist: []float64{
		0.08, // ≤ 10  ms
		0.18, // ≤ 20  ms
		0.30, // ≤ 30  ms
		0.42, // ≤ 40  ms
		0.53, // ≤ 50  ms
		0.61, // ≤ 60  ms
		0.68, // ≤ 70  ms
		0.73, // ≤ 80  ms
		0.77, // ≤ 90  ms
		0.81, // ≤ 100 ms
		0.84, // ≤ 110 ms
		0.86, // ≤ 120 ms
		0.88, // ≤ 130 ms
		0.90, // ≤ 140 ms
		0.92, // ≤ 150 ms
		0.94, // ≤ 160 ms
		0.96, // ≤ 170 ms
		0.97, // ≤ 180 ms
		0.99, // ≤ 190 ms
		1.00, // ≤ 200 ms
	},
	BurstPattern: BurstModel{
		MinPackets:  3,
		MaxPackets:  15,
		PauseMeanMs: 80.0,
		PauseStdMs:  40.0,
	},
	SessionDuration: Distribution{
		MinMs:  5_000,
		MaxMs:  300_000,
		MeanMs: 60_000,
		StdMs:  45_000,
	},
	DNSPatterns: []string{
		"dns.google",
		"cloudflare-dns.com",
		"dns.quad9.net",
	},
}

// youtubeSdProfile represents YouTube 720p streaming: mostly large data
// packets, low IAT during buffering, periodic short pauses.
var youtubeSdProfile = &TrafficProfile{
	Name: "youtube_sd",
	// Predominantly large packets: ≥ 70% payload ≥ 1095 bytes (streaming data).
	PacketSizeDist: []float64{
		0.03, // ≤ 73   bytes (signalling)
		0.06, // ≤ 146
		0.08, // ≤ 219
		0.09, // ≤ 292
		0.10, // ≤ 365
		0.11, // ≤ 438
		0.12, // ≤ 511
		0.13, // ≤ 584
		0.14, // ≤ 657
		0.15, // ≤ 730
		0.17, // ≤ 803
		0.19, // ≤ 876
		0.22, // ≤ 949
		0.26, // ≤ 1022
		0.32, // ≤ 1095
		0.45, // ≤ 1168
		0.62, // ≤ 1241
		0.78, // ≤ 1314
		0.91, // ≤ 1387
		1.00, // ≤ 1460 bytes
	},
	// Low IAT during chunks (< 10 ms), periodic 100-200 ms adaptive buffering.
	IATDist: []float64{
		0.20, // ≤ 10  ms (high-throughput chunk)
		0.38, // ≤ 20  ms
		0.50, // ≤ 30  ms
		0.58, // ≤ 40  ms
		0.64, // ≤ 50  ms
		0.69, // ≤ 60  ms
		0.73, // ≤ 70  ms
		0.76, // ≤ 80  ms
		0.79, // ≤ 90  ms
		0.82, // ≤ 100 ms
		0.84, // ≤ 110 ms
		0.86, // ≤ 120 ms
		0.88, // ≤ 130 ms
		0.90, // ≤ 140 ms
		0.92, // ≤ 150 ms (adaptive buffer window)
		0.94, // ≤ 160 ms
		0.96, // ≤ 170 ms
		0.97, // ≤ 180 ms
		0.99, // ≤ 190 ms
		1.00, // ≤ 200 ms
	},
	BurstPattern: BurstModel{
		MinPackets:  20,
		MaxPackets:  60,
		PauseMeanMs: 2000.0, // adaptive buffer refill pause
		PauseStdMs:  500.0,
	},
	SessionDuration: Distribution{
		MinMs:  60_000,
		MaxMs:  3_600_000,
		MeanMs: 600_000,
		StdMs:  400_000,
	},
	DNSPatterns: []string{
		"googlevideo.com",
		"youtube.com",
		"ytimg.com",
	},
}

// instagramFeedProfile represents Instagram feed scrolling: mixed small API
// responses and large media downloads, human-paced IAT.
var instagramFeedProfile = &TrafficProfile{
	Name: "instagram_feed",
	// Mixed: frequent small API packets + large image/video chunks.
	PacketSizeDist: []float64{
		0.12, // ≤ 73   (API JSON, ACK)
		0.22, // ≤ 146
		0.30, // ≤ 219
		0.36, // ≤ 292
		0.40, // ≤ 365
		0.43, // ≤ 438
		0.46, // ≤ 511
		0.49, // ≤ 584
		0.51, // ≤ 657
		0.53, // ≤ 730
		0.56, // ≤ 803
		0.59, // ≤ 876
		0.63, // ≤ 949
		0.68, // ≤ 1022
		0.74, // ≤ 1095 (image chunks begin)
		0.81, // ≤ 1168
		0.88, // ≤ 1241
		0.93, // ≤ 1314
		0.97, // ≤ 1387
		1.00, // ≤ 1460 bytes
	},
	// Human scroll pace: peaks at 200-500 ms IAT between media loads.
	IATDist: []float64{
		0.04, // ≤ 10  ms (burst within media load)
		0.10, // ≤ 20
		0.17, // ≤ 30
		0.24, // ≤ 40
		0.31, // ≤ 50
		0.37, // ≤ 60
		0.43, // ≤ 70
		0.48, // ≤ 80
		0.52, // ≤ 90
		0.56, // ≤ 100 ms
		0.60, // ≤ 110
		0.63, // ≤ 120
		0.67, // ≤ 130
		0.71, // ≤ 140
		0.76, // ≤ 150 ms (human swipe→load delay)
		0.82, // ≤ 160
		0.88, // ≤ 170
		0.93, // ≤ 180
		0.97, // ≤ 190
		1.00, // ≤ 200 ms
	},
	BurstPattern: BurstModel{
		MinPackets:  5,
		MaxPackets:  25,
		PauseMeanMs: 350.0, // human swipe pause
		PauseStdMs:  150.0,
	},
	SessionDuration: Distribution{
		MinMs:  30_000,
		MaxMs:  900_000,
		MeanMs: 180_000,
		StdMs:  120_000,
	},
	DNSPatterns: []string{
		"instagram.com",
		"cdninstagram.com",
		"fbcdn.net",
	},
}
