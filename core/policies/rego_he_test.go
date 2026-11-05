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
	"fmt"
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
// DefaultMetricConfigurationSource for testing the HE path.
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

// mockFHEComparer is a mock implementation of FHEComparer for testing.
type mockFHEComparer struct {
	// result is the encrypted boolean bytes to return.
	result []byte
	// err is the error to return, if any.
	err error
	// lastOperator, lastTargetValue, lastValueType capture the last call args.
	lastOperator    string
	lastTargetValue string
	lastValueType   string
}

var _ FHEComparer = (*mockFHEComparer)(nil)

func (m *mockFHEComparer) FheCompare(_ context.Context, operator string, targetValue string, actualValue []byte, valueType string) ([]byte, error) {
	m.lastOperator = operator
	m.lastTargetValue = targetValue
	m.lastValueType = valueType
	if m.err != nil {
		return nil, m.err
	}
	return m.result, nil
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
		name        string
		fields      fields
		args        args
		fheResult   []byte
		want        assert.Want[[]*CombinedResult]
		wantErr     assert.WantErr
	}{
		{
			name: "applicable metric with encrypted result",
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
							"adversarialRobustnessScore": structpb.NewStringValue("ZW5jcnlwdGVkLTQyLjQy"),
						},
					}).GetStructValue(),
				},
				src: &mockHEMetricsSource{t: t},
			},
			fheResult: []byte{0x01, 0x02, 0x03, 0x04},
			want: func(t *testing.T, got []*CombinedResult, args ...any) bool {
				if !assert.NotNil(t, got) {
					return false
				}
				if len(got) == 0 {
					t.Error("expected at least one result")
					return false
				}
				if !assert.True(t, got[0].Applicable) {
					return false
				}
				// compliant must be false (cannot be computed for encrypted values)
				if !assert.False(t, got[0].Compliant) {
					return false
				}
				// encrypted_success must be populated
				if len(got[0].ComparisonResult) == 0 {
					t.Error("expected at least one comparison result")
					return false
				}
				return assert.NotNil(t, got[0].ComparisonResult[0].EncryptedSuccess)
			},
			wantErr: assert.NoError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			comparer := &mockFHEComparer{result: tt.fheResult}
			re := &regoEval{
				qc:         tt.fields.qc,
				mrtc:       tt.fields.mrtc,
				pkg:        tt.fields.pkg,
				fheComparer: comparer,
			}
			got, err := re.EvalHE(tt.args.ctx, tt.args.evidence, tt.args.src)

			tt.wantErr(t, err)
			tt.want(t, got)
		})
	}
}

func Test_regoEval_fheCompare(t *testing.T) {
	tests := []struct {
		name         string
		fheResult    []byte
		operator     string
		value        string
		targetTerm   *ast.Term
		wantValueType string
		wantErr      assert.WantErr
	}{
		{
			name:          "number comparison",
			fheResult:     []byte{0xAA, 0xBB},
			operator:      ">=",
			value:         "ZW5jcnlwdGVkLTQyLjQy",
			targetTerm:    ast.NumberTerm("0.5"),
			wantValueType: "number",
			wantErr:       assert.NoError,
		},
		{
			name:          "boolean comparison",
			fheResult:     []byte{0xCC, 0xDD},
			operator:      "==",
			value:         "ZW5jcnlwdGVkLXRydWU=",
			targetTerm:    ast.BooleanTerm(true),
			wantValueType: "boolean",
			wantErr:       assert.NoError,
		},
		{
			name:          "string comparison",
			fheResult:     []byte{0xEE, 0xFF},
			operator:      "==",
			value:         "ZW5jcnlwdGVkLWR1bW15",
			targetTerm:    ast.StringTerm("dummy"),
			wantValueType: "string",
			wantErr:       assert.NoError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			comparer := &mockFHEComparer{result: tt.fheResult}
			re := &regoEval{
				fheComparer: comparer,
			}

			got, err := re.fheCompare(
				rego.BuiltinContext{Context: context.Background()},
				ast.StringTerm(tt.operator),
				ast.StringTerm(tt.value),
				tt.targetTerm,
			)

			tt.wantErr(t, err)
			if err == nil {
				assert.NotNil(t, got)
				// Verify the comparer received the correct valueType
				assert.Equal(t, tt.wantValueType, comparer.lastValueType)
				// Verify the result is a string (base64-encoded encrypted boolean)
				_, ok := got.Value.(ast.String)
				assert.True(t, ok)
			}
		})
	}
}

func Test_regoEval_fheCompare_noComparer(t *testing.T) {
	re := &regoEval{}

	_, err := re.fheCompare(
		rego.BuiltinContext{Context: context.Background()},
		ast.StringTerm(">="),
		ast.StringTerm("ZW5jcnlwdGVkLTQyLjQy"),
		ast.NumberTerm("0.5"),
	)
	assert.Error(t, err)
}

func Test_regoEval_EvalHE_comparerError(t *testing.T) {
	comparer := &mockFHEComparer{err: fmt.Errorf("FHE proxy unavailable")}

	re := &regoEval{
		qc:          newQueryCache(),
		mrtc:        &metricsCache{m: make(map[string][]*assessment.Metric)},
		pkg:         DefaultRegoPackage,
		fheComparer: comparer,
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
				"adversarialRobustnessScore": structpb.NewStringValue("ZW5jcnlwdGVkLTQyLjQy"),
			},
		}).GetStructValue(),
	}

	// When the FHE proxy returns an error, OPA treats the built-in error as
	// undefined, so the metric is evaluated as non-compliant rather than
	// failing the entire evaluation.
	got, err := re.EvalHE(context.Background(), ev, &mockHEMetricsSource{t: t})
	assert.NoError(t, err)
	if len(got) > 0 {
		assert.True(t, got[0].Applicable)
		assert.False(t, got[0].Compliant)
	}
}
