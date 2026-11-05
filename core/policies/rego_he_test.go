// Copyright 2016-2025 Fraunhofer AISEC
//
// SPDX-License-Identifier: Apache-2.0
//
//                                 /$$$$$$  /$$                                     /$$
//                               /$$__  $$|__/                                    | $$
//   /$$$$$$$  /$$$$$$  /$$$$$$$ | $$  \__/ /$$  /$$$$$$  /$$$$$$/$$$$   /$$$$$$  /$$$$$$    /$$$$$$
//  /$$_____/ /$$__  $$| $$__  $$| $$$$    | $$ /$$__  $$| $$_  $$_  $$ |____  $$|_  $$_/   /$$__  $$
// | $$      | $$  \ $$| $$  \ $$| $$_/    | $$| $$  \__/| $$ \ $$ \ $$  /$$$$$$$  | $$    | $$$$$$$$
// | $$      | $$  | $$| $$  | $$| $$      | $$| $$      | $$ | $$ | $$ /$$__  $$  | $$ /$$| $$_____/
// |  $$$$$$$|  $$$$$$/| $$  | $$| $$      | $$| $$      | $$ | $$ | $$|  $$$$$$$  |  $$$$/|  $$$$$$$
// \_______/ \______/ |__/  |__/|__/      |__/|__/      |__/ |__/ |__/ \_______/   \___/   \_______/
//
// This file is part of Confirmate Core.

package policies

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"confirmate.io/core/api/assessment"
	"confirmate.io/core/api/evidence"
	"confirmate.io/core/service/evidence/evidencetest"
	"confirmate.io/core/util/assert"
)

// mockHEMetricsSource implements MetricsSource and
// DefaultMetricConfigurationSource for testing the HE path. It loads metrics
// from the filesystem, same as mockMetricsSource, but also provides
// DefaultMetricConfiguration.
type mockHEMetricsSource struct {
	t *testing.T
}

// Ensure mockHEMetricsSource implements the required interfaces.
var _ MetricsSource = (*mockHEMetricsSource)(nil)
var _ DefaultMetricConfigurationSource = (*mockHEMetricsSource)(nil)

func (m *mockHEMetricsSource) Metrics(_ context.Context) ([]*assessment.Metric, error) {
	return (&mockMetricsSource{t: m.t}).Metrics(context.Background())
}

func (m *mockHEMetricsSource) MetricConfiguration(_ context.Context, targetID string, metric *assessment.Metric) (*assessment.MetricConfiguration, error) {
	return (&mockMetricsSource{t: m.t}).MetricConfiguration(context.Background(), targetID, metric)
}

func (m *mockHEMetricsSource) DefaultMetricConfiguration(_ context.Context, metric *assessment.Metric) (*assessment.MetricConfiguration, error) {
	return (&mockMetricsSource{t: m.t}).MetricConfiguration(context.Background(), "", metric)
}

func (m *mockHEMetricsSource) MetricImplementation(_ context.Context, _ assessment.MetricImplementation_Language, metric *assessment.Metric) (*assessment.MetricImplementation, error) {
	return (&mockMetricsSource{t: m.t}).MetricImplementation(context.Background(), assessment.MetricImplementation_LANGUAGE_REGO, metric)
}

// fakeFHEProxy starts an httptest.Server that responds to /compare requests
// with a configurable result. It returns the server.
func fakeFHEProxy(t *testing.T, result bool) (srv *httptest.Server) {
	t.Helper()
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/compare" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var req fheCompareRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		resp := fheCompareResponse{Result: result}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func Test_regoEval_EvalHE(t *testing.T) {
	type fields struct {
		qc   *queryCache
		mrtc *metricsCache
		pkg  string
	}
	type args struct {
		ctx      context.Context
		evidence *evidence.EvidenceEncrypted
		src      MetricsSource
	}
	tests := []struct {
		name      string
		fields    fields
		args      args
		fheResult bool
		want      assert.Want[[]*CombinedResult]
		wantErr   assert.WantErr
	}{
		{
			name: "applicable metric with compliant result",
			fields: fields{
				qc:   newQueryCache(),
				mrtc: &metricsCache{m: make(map[string][]*assessment.Metric)},
				pkg:  DefaultRegoPackage,
			},
			args: args{
				ctx: context.Background(),
				evidence: &evidence.EvidenceEncrypted{
					Id:                   evidencetest.MockEvidenceID1,
					Timestamp:            timestamppb.Now(),
					TargetOfEvaluationId: evidencetest.MockTargetOfEvaluationID1,
					ToolId:               evidencetest.MockEvidenceToolID1,
					ResourceId:           "dummy",
					ResourceTypes:        []string{"MachineLearningModel"},
					Resource: structpb.NewStructValue(&structpb.Struct{
						Fields: map[string]*structpb.Value{
							"adversarialRobustnessScore": structpb.NewStringValue("encrypted-42.42"),
						},
					}).GetStructValue(),
				},
				src: &mockHEMetricsSource{t: t},
			},
			fheResult: true,
			want: func(t *testing.T, got []*CombinedResult, args ...any) bool {
				if !assert.NotNil(t, got) {
					return false
				}
				if len(got) == 0 {
					t.Error("expected at least one result")
					return false
				}
				return assert.True(t, got[0].Applicable)
			},
			wantErr: assert.NoError,
		},
		{
			name: "applicable metric with non-compliant result",
			fields: fields{
				qc:   newQueryCache(),
				mrtc: &metricsCache{m: make(map[string][]*assessment.Metric)},
				pkg:  DefaultRegoPackage,
			},
			args: args{
				ctx: context.Background(),
				evidence: &evidence.EvidenceEncrypted{
					Id:                   evidencetest.MockEvidenceID1,
					Timestamp:            timestamppb.Now(),
					TargetOfEvaluationId: evidencetest.MockTargetOfEvaluationID1,
					ToolId:               evidencetest.MockEvidenceToolID1,
					ResourceId:           "dummy",
					ResourceTypes:        []string{"MachineLearningModel"},
					Resource: structpb.NewStructValue(&structpb.Struct{
						Fields: map[string]*structpb.Value{
							"adversarialRobustnessScore": structpb.NewStringValue("encrypted-42.42"),
						},
					}).GetStructValue(),
				},
				src: &mockHEMetricsSource{t: t},
			},
			fheResult: false,
			want: func(t *testing.T, got []*CombinedResult, args ...any) bool {
				if !assert.NotNil(t, got) {
					return false
				}
				if len(got) == 0 {
					t.Error("expected at least one result")
					return false
				}
				return assert.False(t, got[0].Compliant)
			},
			wantErr: assert.NoError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := fakeFHEProxy(t, tt.fheResult)
			re := &regoEval{
				qc:            tt.fields.qc,
				mrtc:          tt.fields.mrtc,
				pkg:           tt.fields.pkg,
				fheAddress:    srv.URL,
				fheHTTPClient: srv.Client(),
			}
			got, err := re.EvalHE(tt.args.ctx, tt.args.evidence, tt.args.src)

			tt.wantErr(t, err)
			tt.want(t, got)
		})
	}
}

func Test_regoEval_fheCompare(t *testing.T) {
	tests := []struct {
		name       string
		fheResult  bool
		operator   string
		value      string
		targetTerm *ast.Term
		wantResult bool
		wantErr    assert.WantErr
	}{
		{
			name:       "number comparison returns true",
			fheResult:  true,
			operator:   ">=",
			value:      "encrypted-42.42",
			targetTerm: ast.NumberTerm("0.5"),
			wantResult: true,
			wantErr:    assert.NoError,
		},
		{
			name:       "number comparison returns false",
			fheResult:  false,
			operator:   ">=",
			value:      "encrypted-42.42",
			targetTerm: ast.NumberTerm("0.5"),
			wantResult: false,
			wantErr:    assert.NoError,
		},
		{
			name:       "boolean comparison",
			fheResult:  true,
			operator:   "==",
			value:      "encrypted-true",
			targetTerm: ast.BooleanTerm(true),
			wantResult: true,
			wantErr:    assert.NoError,
		},
		{
			name:       "string comparison",
			fheResult:  true,
			operator:   "==",
			value:      "encrypted-dummy",
			targetTerm: ast.StringTerm("dummy"),
			wantResult: true,
			wantErr:    assert.NoError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := fakeFHEProxy(t, tt.fheResult)
			re := &regoEval{
				fheAddress:    srv.URL,
				fheHTTPClient: srv.Client(),
			}

			got, err := re.fheCompare(
				rego.BuiltinContext{Context: context.Background()},
				ast.StringTerm(tt.operator),
				ast.StringTerm(tt.value),
				tt.targetTerm,
			)

			tt.wantErr(t, err)
			if err == nil {
				assert.Equal(t, ast.BooleanTerm(tt.wantResult).String(), got.String())
			}
		})
	}
}

func Test_regoEval_EvalHE_proxyError(t *testing.T) {
	// When the FHE proxy returns an error, OPA's default behavior treats the
	// built-in error as undefined, so the metric is evaluated as non-compliant
	// rather than failing the entire evaluation.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprint(w, "FHE proxy unavailable")
	}))
	t.Cleanup(srv.Close)

	re := &regoEval{
		qc:            newQueryCache(),
		mrtc:          &metricsCache{m: make(map[string][]*assessment.Metric)},
		pkg:           DefaultRegoPackage,
		fheAddress:    srv.URL,
		fheHTTPClient: srv.Client(),
	}

	ev := &evidence.EvidenceEncrypted{
		Id:                   evidencetest.MockEvidenceID1,
		Timestamp:            timestamppb.Now(),
		TargetOfEvaluationId: evidencetest.MockTargetOfEvaluationID1,
		ToolId:               evidencetest.MockEvidenceToolID1,
		ResourceId:           "dummy",
		ResourceTypes:        []string{"MachineLearningModel"},
		Resource: structpb.NewStructValue(&structpb.Struct{
			Fields: map[string]*structpb.Value{
				"adversarialRobustnessScore": structpb.NewStringValue("encrypted-42.42"),
			},
		}).GetStructValue(),
	}

	got, err := re.EvalHE(context.Background(), ev, &mockHEMetricsSource{t: t})
	assert.NoError(t, err)
	// The metric should still be applicable (applicability doesn't use fhe_compare)
	if len(got) > 0 {
		assert.True(t, got[0].Applicable)
		assert.False(t, got[0].Compliant)
	}
}
