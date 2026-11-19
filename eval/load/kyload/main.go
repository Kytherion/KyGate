// Command kyload loads a running KyGate and reports what it measured. It has
// two parts:
//
//	kyload standin [flags]   a stand-in model provider, so a load test spends nothing
//	kyload run [flags]       send load to a gateway and report latency, throughput, errors
//
// Point KyGate at the stand-in with OPENAI_BASE_URL and ANTHROPIC_BASE_URL
// (any key value works), then run load against KyGate. See eval/load/README.md.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"time"

	"github.com/Kytherion/KyGate/eval/load/run"
	"github.com/Kytherion/KyGate/eval/load/standin"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "standin":
		standinCmd(os.Args[2:])
	case "run":
		runCmd(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `kyload: load tests for KyGate

  kyload standin [-listen 127.0.0.1:9100] [-first-byte 300ms] [-chunks 20] [-chunk-gap 25ms] [-filler 40]
      A stand-in OpenAI and Anthropic provider. Start KyGate with
      OPENAI_BASE_URL=http://127.0.0.1:9100 and OPENAI_API_KEY=standin (and the
      ANTHROPIC_ variables) so that no load reaches a real provider.

  kyload run -url http://127.0.0.1:4000 -key kg-... [-api openai|anthropic] [-model M]
             [-c 32] [-n 2000 | -d 30s] [-repeat 0.5] [-stream 0.2] [-sensitive 0.5]
             [-pool 20] [-ramp 1s] [-json]
      Sends load and reports latency, time to first byte, requests per second,
      cache hits, and errors. Every answer is checked: a caller must get its own
      card number back. The key can also come from KYGATE_LOAD_KEY.
`)
	os.Exit(2)
}

func standinCmd(args []string) {
	fs := flag.NewFlagSet("standin", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:9100", "address to listen on")
	p := &standin.Provider{}
	fs.DurationVar(&p.FirstByte, "first-byte", 300*time.Millisecond, "wait before each answer starts, like a model's time to first token")
	fs.IntVar(&p.Chunks, "chunks", 20, "pieces of a streamed answer")
	fs.DurationVar(&p.ChunkGap, "chunk-gap", 25*time.Millisecond, "wait between pieces of a streamed answer")
	fs.IntVar(&p.Filler, "filler", 40, "words after the echo in each answer")
	fs.Parse(args)
	srv := &http.Server{Addr: *listen, Handler: p}
	go func() {
		t := time.NewTicker(10 * time.Second)
		last := int64(0)
		for range t.C {
			if n := p.Calls(); n != last {
				log.Printf("%d model calls answered (%d in the last 10 s)", n, n-last)
				last = n
			}
		}
	}()
	log.Printf("stand-in provider on http://%s (first byte %s, %d pieces %s apart); it never calls a real model", *listen, p.FirstByte, p.Chunks, p.ChunkGap)
	log.Fatal(srv.ListenAndServe())
}

func runCmd(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	var cfg run.Config
	fs.StringVar(&cfg.URL, "url", "http://127.0.0.1:4000", "KyGate's model API")
	fs.StringVar(&cfg.Key, "key", os.Getenv("KYGATE_LOAD_KEY"), "a virtual key (default: KYGATE_LOAD_KEY)")
	fs.StringVar(&cfg.API, "api", "openai", "openai or anthropic")
	fs.StringVar(&cfg.Model, "model", "", "model name (default: gpt-4o-mini, or claude-sonnet-5-5 with -api anthropic)")
	fs.IntVar(&cfg.Concurrency, "c", 32, "requests in flight")
	fs.IntVar(&cfg.Requests, "n", 0, "requests to send (default 2000 when -d is not set)")
	fs.DurationVar(&cfg.Duration, "d", 0, "send for this long instead of -n")
	fs.Float64Var(&cfg.Repeat, "repeat", 0.5, "share of requests that repeat an earlier prompt (exact-cache hits)")
	fs.Float64Var(&cfg.Stream, "stream", 0.2, "share of requests streamed")
	fs.Float64Var(&cfg.Sensitive, "sensitive", 0.5, "share of requests that carry a card number to mask")
	fs.IntVar(&cfg.Pool, "pool", 20, "distinct prompts that repeats draw from")
	fs.DurationVar(&cfg.Ramp, "ramp", time.Second, "start the workers spread over this time")
	fs.Int64Var(&cfg.Seed, "seed", time.Now().UnixNano(), "random seed")
	asJSON := fs.Bool("json", false, "print the result as JSON")
	fs.Parse(args)
	if cfg.Key == "" {
		log.Fatal("set -key or KYGATE_LOAD_KEY to a virtual key")
	}
	if cfg.Model == "" {
		cfg.Model = "gpt-4o-mini"
		if cfg.API == "anthropic" {
			cfg.Model = "claude-sonnet-5-5"
		}
	}
	if cfg.Requests == 0 && cfg.Duration == 0 {
		cfg.Requests = 2000
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	res, err := run.Run(ctx, cfg)
	if err != nil {
		log.Fatal(err)
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(res)
		return
	}
	fmt.Printf("%d requests in %s: %.0f per second, concurrency %d\n", res.Requests, res.Elapsed.Round(time.Millisecond), res.RPS, cfg.Concurrency)
	fmt.Printf("  errors           %d (wrong answers %d)\n", res.Errors, res.Wrong)
	fmt.Printf("  cache hits       %d\n", res.Hits)
	fmt.Printf("  latency          %s\n", res.Latency)
	fmt.Printf("  first byte       %s\n", res.TTFB)
	fmt.Printf("  hit, first byte  %s\n", res.HitTTFB)
	fmt.Printf("  model call       %s\n", res.MissLatency)
	fmt.Printf("  whole stream     %s\n", res.StreamTotal)
	codes := make([]int, 0, len(res.ByStatus))
	for c := range res.ByStatus {
		codes = append(codes, c)
	}
	sort.Ints(codes)
	for _, c := range codes {
		fmt.Printf("  status %d       %d\n", c, res.ByStatus[c])
	}
	for msg, n := range res.Samples {
		fmt.Printf("  error x%d: %s\n", n, msg)
	}
	if res.Errors > 0 {
		os.Exit(1)
	}
}
