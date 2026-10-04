package runner

import (
	"context"
	"fmt"
	"runtime"

	"github.com/OpenStack-Policy-Agent/OSPA/pkg/audit"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/auth"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/orchestrator"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/policy"
	"github.com/OpenStack-Policy-Agent/OSPA/pkg/report"
)

// Options configures a single audit run.
type Options struct {
	Cloud string
	// Session, when set, is used instead of authenticating via Cloud/clouds.yaml.
	Session       *auth.Session
	Policy        *policy.Policy
	Workers       int
	Apply         bool
	AllTenants    bool
	JobsBuffer    int
	ResultsBuffer int
	AllowActions  []string
	// Writer receives non-compliant / error findings (CLI file output).
	Writer report.ResultWriter
	// OnFinding is called for every written finding (UI store).
	OnFinding func(report.Finding)
	// OnResult is called for every audit result (optional).
	OnResult func(*audit.Result)
}

// Outcome is the final summary of a completed run.
type Outcome struct {
	Summary report.Summary
}

// Run authenticates, executes the orchestrator, and returns a summary.
// Cancellation of ctx stops discovery/workers.
func Run(ctx context.Context, opts Options) (Outcome, error) {
	if opts.Session == nil && opts.Cloud == "" {
		return Outcome{}, fmt.Errorf("cloud or session is required")
	}
	if opts.Policy == nil {
		return Outcome{}, fmt.Errorf("policy is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	session := opts.Session
	if session == nil {
		var err error
		session, err = auth.NewSession(opts.Cloud)
		if err != nil {
			return Outcome{}, fmt.Errorf("authentication failed: %w", err)
		}
	}

	workers := opts.Policy.EffectiveWorkers(opts.Workers)
	if workers <= 0 {
		workers = runtime.NumCPU() * 8
	}

	orch := orchestrator.NewOrchestratorWithContext(ctx, opts.Policy, session, workers, opts.Apply, opts.AllTenants)
	if opts.JobsBuffer > 0 || opts.ResultsBuffer > 0 {
		orch.SetBuffers(opts.JobsBuffer, opts.ResultsBuffer)
	}
	orch.SetRemediationAllowlist(opts.AllowActions)
	defer orch.Stop()

	resultsChan, err := orch.Run()
	if err != nil {
		return Outcome{}, fmt.Errorf("start orchestrator: %w", err)
	}

	writer := opts.Writer
	if opts.OnFinding != nil {
		writer = multiWriter{primary: opts.Writer, onFinding: opts.OnFinding}
	}

	summary := report.ConsumeResults(tapResults(resultsChan, opts.OnResult), writer)
	return Outcome{Summary: summary}, nil
}

func tapResults(in <-chan *audit.Result, on func(*audit.Result)) <-chan *audit.Result {
	if on == nil {
		return in
	}
	out := make(chan *audit.Result)
	go func() {
		defer close(out)
		for r := range in {
			on(r)
			out <- r
		}
	}()
	return out
}

type multiWriter struct {
	primary   report.ResultWriter
	onFinding func(report.Finding)
}

func (w multiWriter) WriteResult(r *audit.Result) error {
	f := report.FindingFromResult(r)
	w.onFinding(f)
	if w.primary != nil {
		return w.primary.WriteResult(r)
	}
	return nil
}

func (w multiWriter) Close() error {
	if w.primary != nil {
		return w.primary.Close()
	}
	return nil
}
