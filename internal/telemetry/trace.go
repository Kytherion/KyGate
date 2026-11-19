package telemetry

// Traces (capability OB-5). They are off unless an OTLP endpoint is set with
// the standard OpenTelemetry variables, so a default installation sends
// nothing anywhere:
//
//	OTEL_EXPORTER_OTLP_ENDPOINT          for example http://localhost:4318
//	OTEL_EXPORTER_OTLP_TRACES_ENDPOINT   the traces endpoint alone
//	OTEL_EXPORTER_OTLP_HEADERS           for example an authorization header
//	OTEL_TRACES_SAMPLER, _ARG            for example parentbased_traceidratio, 0.1
//	OTEL_SERVICE_NAME                    kygate by default
//
// Spans carry metadata only: names of models and provider keys, outcomes,
// cache results, token counts, costs, finding types and counts. Never prompt
// or answer text, never a value, never a key (invariant 3, 10).

import (
	"context"
	"os"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// TracingEndpoint returns the OTLP endpoint traces go to, or "" when tracing is off.
func TracingEndpoint() string {
	for _, k := range []string{"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "OTEL_EXPORTER_OTLP_ENDPOINT"} {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return ""
}

// SetupTracing installs the OTLP exporter when an endpoint is configured. The
// returned function flushes and stops it.
func SetupTracing(ctx context.Context, version string) (shutdown func(context.Context) error, err error) {
	noop := func(context.Context) error { return nil }
	if TracingEndpoint() == "" || strings.EqualFold(os.Getenv("OTEL_SDK_DISABLED"), "true") {
		return noop, nil
	}
	exp, err := otlptracehttp.New(ctx)
	if err != nil {
		return noop, err
	}
	// Later detectors win: the environment can rename the service.
	res, err := resource.New(ctx,
		resource.WithAttributes(attribute.String("service.name", "kygate"), attribute.String("service.version", version)),
		resource.WithTelemetrySDK(), resource.WithFromEnv())
	if err != nil {
		return noop, err
	}
	tp := sdktrace.NewTracerProvider(sdktrace.WithBatcher(exp), sdktrace.WithResource(res))
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	return tp.Shutdown, nil
}

// Tracer is KyGate's tracer. It is a no-op until SetupTracing installs an
// exporter, so instrumented code costs nothing when tracing is off.
func Tracer() trace.Tracer { return otel.Tracer("kygate") }
