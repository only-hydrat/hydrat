package agentapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"

	"github.com/only-hydrat/hydrat/internal/dataplane"
)

type recoveryPlanRequest struct {
	Plan       dataplane.DesiredPlan    `json:"plan"`
	Recoveries []dataplane.FlowRecovery `json:"recoveries"`
}

var errRecoveryUnsupported = errors.New("gateway does not support targeted flow recovery")

type recoveryApplierContract interface {
	ApplyWithRecovery(context.Context, dataplane.DesiredPlan, []dataplane.FlowRecovery) error
}

func (client *Client) ApplyWithRecovery(ctx context.Context, plan dataplane.DesiredPlan, recoveries []dataplane.FlowRecovery) error {
	if err := plan.Validate(); err != nil {
		return err
	}
	if err := dataplane.ValidateFlowRecoveries(plan, recoveries); err != nil {
		return err
	}
	err := client.applyRequest(ctx, "/v1/plan/recovery", recoveryPlanRequest{Plan: plan, Recoveries: recoveries})
	if errors.Is(err, errRecoveryUnsupported) {
		// A mixed-version rollout must not stop emergency route replacement.
		// Only endpoint absence/explicit non-support is safe to downgrade;
		// never replay ambiguous failures as an ordinary plan.
		log.Print("gateway lacks targeted TCP recovery; applying replacement without flow reset")
		return client.Apply(ctx, plan)
	}
	return err
}

func (server *Server) applyRecoveryPlan(response http.ResponseWriter, request *http.Request) {
	request.Body = http.MaxBytesReader(response, request.Body, server.maxPlanSize)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	var payload recoveryPlanRequest
	if err := decoder.Decode(&payload); err != nil {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "invalid recovery plan"})
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "request must contain one recovery plan"})
		return
	}
	if payload.Plan.Validate() != nil || dataplane.ValidateFlowRecoveries(payload.Plan, payload.Recoveries) != nil {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "invalid recovery scope"})
		return
	}
	applier, ok := server.applier.(recoveryApplierContract)
	if !ok {
		writeJSON(response, http.StatusNotImplemented, map[string]string{"error": "flow recovery unavailable"})
		return
	}
	writeApplyResult(response, applier.ApplyWithRecovery(request.Context(), payload.Plan, payload.Recoveries))
}
