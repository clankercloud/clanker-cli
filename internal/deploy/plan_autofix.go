package deploy

import (
	"regexp"
	"strings"

	"github.com/bgdnvk/clanker/internal/maker"
)

// ApplyGenericPlanAutofix runs provider-agnostic dedup passes that collapse
// redundant launch/terminate cycles the LLM tends to produce when it "fixes"
// user-data or startup scripts by appending new run-instances commands.
func ApplyGenericPlanAutofix(plan *maker.Plan, logf func(string, ...any)) *maker.Plan {
	if plan == nil || len(plan.Commands) == 0 {
		return plan
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}

	removed := pruneRedundantLaunchCycles(plan)
	if removed > 0 {
		logf("[deploy] generic autofix: collapsed %d redundant launch-cycle command(s)", removed)
	}

	// Dedup read-only describe/get commands targeting the same resource.
	roRemoved := pruneRedundantReadOnly(plan)
	if roRemoved > 0 {
		logf("[deploy] generic autofix: removed %d redundant read-only command(s)", roRemoved)
	}

	// Generic SSM semantic dedup (works for any project, not just OpenClaw).
	ssmRemoved := pruneSSMSemanticDuplicatesGeneric(plan)
	if ssmRemoved > 0 {
		logf("[deploy] generic autofix: removed %d redundant SSM command(s)", ssmRemoved)
	}

	// Remove commands referencing placeholders that no command produces.
	orphanRemoved := pruneOrphanedPlaceholderRefs(plan)
	if orphanRemoved > 0 {
		logf("[deploy] generic autofix: removed %d orphaned-placeholder command(s)", orphanRemoved)
	}

	return plan
}

// pruneRedundantLaunchCycles detects multiple ec2 run-instances (or ecs
// run-task) commands that target the same project and keeps only the LAST
// one — the most refined version with correct user-data. It also removes
// the terminate→wait→deregister chains for the earlier instances whose
// produced IDs are consumed only by cleanup commands.
func pruneRedundantLaunchCycles(plan *maker.Plan) int {
	if len(plan.Commands) < 2 {
		return 0
	}

	// Identify all run-instances indices and the placeholder name each produces.
	type launchInfo struct {
		idx        int
		producesID string // e.g. INSTANCE_ID, NEW_INSTANCE_ID, FIXED_INSTANCE_ID
	}
	var launches []launchInfo
	for i, cmd := range plan.Commands {
		if !isEC2RunInstances(cmd.Args) {
			continue
		}
		idKey := ""
		for k := range cmd.Produces {
			ku := strings.ToUpper(strings.TrimSpace(k))
			if strings.Contains(ku, "INSTANCE") && strings.Contains(ku, "ID") {
				idKey = k
				break
			}
		}
		launches = append(launches, launchInfo{idx: i, producesID: idKey})
	}
	if len(launches) < 2 {
		return 0
	}

	// Keep only the LAST run-instances. Mark earlier ones + their lifecycle
	// commands (terminate, wait terminated, deregister for that instance ID)
	// for removal.
	keep := launches[len(launches)-1]
	drop := make(map[int]struct{})

	for _, li := range launches[:len(launches)-1] {
		drop[li.idx] = struct{}{}
		if li.producesID == "" {
			continue
		}
		// Find commands that only reference this instance ID placeholder
		placeholder := "<" + li.producesID + ">"
		for j, cmd := range plan.Commands {
			if j == li.idx || j == keep.idx {
				continue
			}
			if _, already := drop[j]; already {
				continue
			}
			if isLaunchLifecycleCommand(cmd.Args) && argsContain(cmd.Args, placeholder) {
				drop[j] = struct{}{}
			}
		}
	}

	if len(drop) == 0 {
		return 0
	}

	filtered := make([]maker.Command, 0, len(plan.Commands)-len(drop))
	for i, cmd := range plan.Commands {
		if _, ok := drop[i]; ok {
			continue
		}
		filtered = append(filtered, cmd)
	}
	plan.Commands = filtered
	return len(drop)
}

// isEC2RunInstances returns true for ec2 run-instances commands.
func isEC2RunInstances(args []string) bool {
	if len(args) < 2 {
		return false
	}
	svc := strings.ToLower(strings.TrimSpace(args[0]))
	op := strings.ToLower(strings.TrimSpace(args[1]))
	return svc == "ec2" && op == "run-instances"
}

// isLaunchLifecycleCommand returns true for commands that are part of an
// instance launch cycle: terminate, wait, deregister, register, describe-status.
func isLaunchLifecycleCommand(args []string) bool {
	if len(args) < 2 {
		return false
	}
	svc := strings.ToLower(strings.TrimSpace(args[0]))
	op := strings.ToLower(strings.TrimSpace(args[1]))

	switch {
	case svc == "ec2" && op == "terminate-instances":
		return true
	case svc == "ec2" && op == "wait":
		// instance-running, instance-terminated
		return true
	case svc == "ec2" && op == "describe-instance-status":
		return true
	case svc == "elbv2" && op == "register-targets":
		return true
	case svc == "elbv2" && op == "deregister-targets":
		return true
	case svc == "elbv2" && op == "wait":
		return true
	case svc == "elbv2" && op == "describe-target-health":
		return true
	}
	return false
}

// argsContain checks if any arg contains the given substring.
func argsContain(args []string, sub string) bool {
	for _, a := range args {
		if strings.Contains(a, sub) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Generic SSM semantic dedup
// ---------------------------------------------------------------------------

// classifySSMScriptGeneric returns a generic semantic category for a shell
// script embedded in an SSM command. No project-specific patterns.
func classifySSMScriptGeneric(script string) string {
	if script == "" {
		return ""
	}
	l := strings.ToLower(script)

	hasStart := strings.Contains(l, "docker compose up") || strings.Contains(l, "docker-compose up") || strings.Contains(l, "docker run")
	hasStop := (strings.Contains(l, "docker compose down") || strings.Contains(l, "docker compose stop") || strings.Contains(l, "docker-compose down")) && !hasStart
	hasEnvWrite := (strings.Contains(l, "> .env") || strings.Contains(l, ">> .env") || strings.Contains(l, "cat >")) && strings.Contains(l, ".env")
	hasECRPull := strings.Contains(l, "ecr get-login-password") || (strings.Contains(l, "docker pull") && strings.Contains(l, ".dkr.ecr."))
	hasDiag := (strings.Contains(l, "docker logs") || strings.Contains(l, "docker ps") || strings.Contains(l, "curl -s") || strings.Contains(l, "health")) && !hasStart
	hasClone := strings.Contains(l, "git clone")
	hasMkdir := strings.Contains(l, "mkdir -p") && !hasClone && !hasStart && !hasEnvWrite

	// Priority: clone > start > stop > env > ecr > diag > mkdir
	switch {
	case hasClone:
		return "ssm-clone"
	case hasStart:
		return "ssm-service-start"
	case hasStop:
		return "ssm-service-stop"
	case hasEnvWrite && !hasStart:
		return "ssm-env-setup"
	case hasECRPull:
		return "ssm-ecr-pull"
	case hasDiag:
		return "ssm-diagnostics"
	case hasMkdir:
		return "ssm-mkdir"
	}
	return ""
}

// classifySSMIntentGeneric classifies an SSM send-command generically.
func classifySSMIntentGeneric(args []string) string {
	if len(args) < 4 {
		return ""
	}
	svc := strings.ToLower(strings.TrimSpace(args[0]))
	op := strings.ToLower(strings.TrimSpace(args[1]))
	if svc != "ssm" || op != "send-command" {
		return ""
	}
	script := extractSSMScriptFromArgs(args)
	return classifySSMScriptGeneric(script)
}

// pruneSSMSemanticDuplicatesGeneric collapses SSM send-command steps that
// repeat the same generic intent. Keeps the LAST of each category.
func pruneSSMSemanticDuplicatesGeneric(plan *maker.Plan) int {
	if plan == nil || len(plan.Commands) < 2 {
		return 0
	}

	type tagged struct {
		idx      int
		category string
	}

	items := make([]tagged, len(plan.Commands))
	for i, cmd := range plan.Commands {
		items[i] = tagged{idx: i, category: classifySSMIntentGeneric(cmd.Args)}
	}

	lastOfCategory := map[string]int{}
	for _, t := range items {
		if t.category != "" {
			lastOfCategory[t.category] = t.idx
		}
	}

	filtered := make([]maker.Command, 0, len(plan.Commands))
	removed := 0
	for i, cmd := range plan.Commands {
		cat := items[i].category
		if cat == "" || items[i].idx == lastOfCategory[cat] {
			filtered = append(filtered, cmd)
		} else {
			removed++
		}
	}
	if removed > 0 {
		plan.Commands = filtered
	}
	return removed
}

// ---------------------------------------------------------------------------
// Orphaned placeholder pruning
// ---------------------------------------------------------------------------

// orphanPlaceholderRe matches <UPPER_CASE_KEY> placeholders in command args.
var orphanPlaceholderRe = regexp.MustCompile(`<([A-Z][A-Z0-9_]+)>`)

// pruneOrphanedPlaceholderRefs removes commands that reference a <KEY>
// placeholder where no command in the plan produces that key. Cascades:
// if a dropped command itself produces something, dependents are also dropped.
func pruneOrphanedPlaceholderRefs(plan *maker.Plan) int {
	if plan == nil || len(plan.Commands) < 2 {
		return 0
	}

	drop := map[int]bool{}

	for changed := true; changed; {
		changed = false
		// Rebuild produced set excluding dropped commands
		produced := map[string]bool{}
		for i, cmd := range plan.Commands {
			if drop[i] {
				continue
			}
			for k := range cmd.Produces {
				produced[strings.TrimSpace(k)] = true
			}
		}

		for i, cmd := range plan.Commands {
			if drop[i] {
				continue
			}
			for _, arg := range cmd.Args {
				matches := orphanPlaceholderRe.FindAllStringSubmatch(arg, -1)
				for _, m := range matches {
					if !produced[m[1]] {
						drop[i] = true
						changed = true
						break
					}
				}
				if drop[i] {
					break
				}
			}
		}
	}

	if len(drop) == 0 {
		return 0
	}

	filtered := make([]maker.Command, 0, len(plan.Commands)-len(drop))
	for i, cmd := range plan.Commands {
		if !drop[i] {
			filtered = append(filtered, cmd)
		}
	}
	plan.Commands = filtered
	return len(drop)
}

// ---------------------------------------------------------------------------
// Read-only command dedup
// ---------------------------------------------------------------------------

// pruneRedundantReadOnly deduplicates read-only commands (describe-*, get-*)
// that target the same resource. Keeps only the last occurrence per
// {service, operation, target} group. Skips commands with produces.
func pruneRedundantReadOnly(plan *maker.Plan) int {
	if plan == nil || len(plan.Commands) < 2 {
		return 0
	}

	type roKey struct {
		service string
		op      string
		target  string
	}

	isReadOnlyOp := func(op string) bool {
		return strings.HasPrefix(op, "describe-") ||
			strings.HasPrefix(op, "get-") ||
			strings.HasPrefix(op, "list-")
	}

	// Extract primary target resource from args.
	primaryTarget := func(args []string) string {
		targets := []string{"--instance-ids", "--id", "--target-group-arn",
			"--names", "--load-balancer-arn", "--load-balancer-arns"}
		for i := 0; i < len(args)-1; i++ {
			flag := strings.TrimSpace(args[i])
			for _, tf := range targets {
				if strings.EqualFold(flag, tf) {
					return strings.TrimSpace(args[i+1])
				}
			}
		}
		return ""
	}

	groups := map[roKey][]int{}
	for i, cmd := range plan.Commands {
		if len(cmd.Args) < 2 {
			continue
		}
		svc := strings.ToLower(strings.TrimSpace(cmd.Args[0]))
		op := strings.ToLower(strings.TrimSpace(cmd.Args[1]))
		if !isReadOnlyOp(op) {
			continue
		}
		// Skip commands that produce values needed downstream
		if len(cmd.Produces) > 0 {
			continue
		}
		target := primaryTarget(cmd.Args)
		key := roKey{svc, op, target}
		groups[key] = append(groups[key], i)
	}

	drop := map[int]bool{}
	for _, indices := range groups {
		if len(indices) < 2 {
			continue
		}
		// Keep only the last occurrence
		for _, idx := range indices[:len(indices)-1] {
			drop[idx] = true
		}
	}

	if len(drop) == 0 {
		return 0
	}

	filtered := make([]maker.Command, 0, len(plan.Commands)-len(drop))
	for i, cmd := range plan.Commands {
		if !drop[i] {
			filtered = append(filtered, cmd)
		}
	}
	plan.Commands = filtered
	return len(drop)
}
