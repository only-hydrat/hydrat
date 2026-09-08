package gateway

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

type Runner interface {
	Run(context.Context, string, ...string) error
	Output(context.Context, string, ...string) ([]byte, error)
}

// TransparentRoutingRulePriority is owned exclusively by Hydrat inside the
// gateway network namespace.
const TransparentRoutingRulePriority = 10000

type Bootstrap struct {
	Runner          Runner
	Interface       string
	WireGuardConfig string
	NFTConfig       string
}

func (bootstrap Bootstrap) Apply(ctx context.Context) error {
	if bootstrap.Runner == nil {
		bootstrap.Runner = ExecRunner{}
	}
	if bootstrap.Interface == "" || bootstrap.WireGuardConfig == "" || bootstrap.NFTConfig == "" {
		return errors.New("gateway bootstrap paths and interface are required")
	}
	if err := bootstrap.Runner.Run(ctx, "ip", "link", "show", "dev", bootstrap.Interface); err != nil {
		if err := bootstrap.Runner.Run(ctx, "wg-quick", "up", bootstrap.WireGuardConfig); err != nil {
			return fmt.Errorf("start WireGuard: %w", err)
		}
	}
	if err := ensureTransparentRoutingRule(ctx, bootstrap.Runner); err != nil {
		return err
	}
	if err := bootstrap.Runner.Run(ctx, "ip", "route", "replace", "local", "0.0.0.0/0", "dev", "lo", "table", "100"); err != nil {
		return fmt.Errorf("configure transparent routing: %w", err)
	}
	if err := bootstrap.Runner.Run(ctx, "nft", "-f", bootstrap.NFTConfig); err != nil {
		return fmt.Errorf("load nftables base policy: %w", err)
	}
	return nil
}

func ensureTransparentRoutingRule(ctx context.Context, runner Runner) error {
	exists, err := inspectTransparentRoutingRule(ctx, runner)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}

	priority := strconv.Itoa(TransparentRoutingRulePriority)
	err = runner.Run(ctx, "ip", "-4", "rule", "add", "priority", priority, "fwmark", "1", "lookup", "100")
	if err == nil {
		return nil
	}
	if !strings.Contains(strings.ToLower(err.Error()), "file exists") {
		return fmt.Errorf("add Hydrat policy rule at priority %d: %w", TransparentRoutingRulePriority, err)
	}
	exists, inspectErr := inspectTransparentRoutingRule(ctx, runner)
	if inspectErr != nil {
		return fmt.Errorf("verify Hydrat policy rule after EEXIST: %w", inspectErr)
	}
	if !exists {
		return fmt.Errorf("priority %d did not contain the Hydrat policy rule after EEXIST", TransparentRoutingRulePriority)
	}
	return nil
}

func inspectTransparentRoutingRule(ctx context.Context, runner Runner) (bool, error) {
	priority := strconv.Itoa(TransparentRoutingRulePriority)
	output, err := runner.Output(ctx, "ip", "-4", "-o", "rule", "show", "priority", priority)
	if err != nil {
		return false, fmt.Errorf("inspect Hydrat policy rule priority %d: %w", TransparentRoutingRulePriority, err)
	}
	var rules []string
	for _, line := range strings.Split(string(output), "\n") {
		if normalized := strings.Join(strings.Fields(line), " "); normalized != "" {
			rules = append(rules, normalized)
		}
	}
	expected := fmt.Sprintf("%d: from all fwmark 0x1 lookup 100", TransparentRoutingRulePriority)
	if len(rules) == 0 {
		return false, nil
	}
	if len(rules) == 1 && rules[0] == expected {
		return true, nil
	}
	return false, fmt.Errorf(
		"Hydrat policy rule priority %d is occupied by conflicting rules: %q",
		TransparentRoutingRulePriority,
		rules,
	)
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, name string, args ...string) error {
	_, err := (ExecRunner{}).Output(ctx, name, args...)
	return err
}

func (ExecRunner) Output(ctx context.Context, name string, args ...string) ([]byte, error) {
	output, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("%s: %w: %s", name, err, string(output))
	}
	return output, nil
}
