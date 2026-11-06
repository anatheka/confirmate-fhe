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
	"encoding/base64"
	"fmt"
	"log/slog"
	"strings"

	"confirmate.io/core/api/assessment"
	"confirmate.io/core/api/evidence"
	"confirmate.io/core/util"

	"connectrpc.com/connect"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/open-policy-agent/opa/v1/types"
	"google.golang.org/protobuf/types/known/structpb"
)

// EvalHE evaluates a given encrypted evidence against all available Rego
// policies and returns the result of all policies that were considered to be
// applicable. It uses the fhe_compare built-in to delegate comparisons to the
// FHE proxy for homomorphic evaluation. The encrypted boolean results are
// stored in ComparisonResult.encrypted_success; the plaintext success and
// compliant fields are always false because the encrypted results cannot be
// evaluated in Rego.
func (re *regoEval) EvalHE(ctx context.Context, ev *evidence.EvidenceEncrypted, src MetricsSource) (data []*CombinedResult, err error) {
	var (
		baseDir string
		m       map[string]any
		types   []string
	)

	baseDir = "."

	// Convert the encrypted resource (google.protobuf.Struct) to a map for
	// Rego input. The incoming Struct is nested under the resource type
	// key (e.g. {"machineLearningModel": {"adversarialRobustnessScore": "..."}}),
	// but the Rego metrics expect flat access (input.adversarialRobustnessScore),
	// matching the plaintext ontology.ResourceMap output. We unwrap the
	// single nested key to produce a flat map.
	if ev.Resource != nil {
		m = unwrapEncryptedResource(ev.Resource.AsMap())
	} else {
		m = make(map[string]any)
	}

	// Add the resource types to the input map, so metrics can check
	// applicability via input.type[_] == "MachineLearningModel".
	types = ev.GetResourceTypes()
	m["type"] = types

	key := createKeyFromEncrypted(ev, types)

	re.mrtc.RLock()
	cached := re.mrtc.m[key]
	re.mrtc.RUnlock()

	if cached == nil {
		metrics, err := src.Metrics(ctx)
		if err != nil {
			return nil, fmt.Errorf("could not retrieve metric definitions: %w", err)
		}

		re.mrtc.Lock()

		cached = []*assessment.Metric{}
		for _, metric := range metrics {
			runMap, err := re.evalMapHE(ctx, baseDir, ev.GetTargetOfEvaluationId(), metric, m, src)
			if err != nil {
				if connect.CodeOf(err) == connect.CodeNotFound && (strings.Contains(err.Error(), "implementation for metric not found") ||
					strings.Contains(err.Error(), "metric configuration not found")) {
					slog.Error("Metric implementation or configuration not found. Skipping metric", "metric_name", metric.GetName(), "metric_id", metric.GetId(), "error", err)
					continue
				}

				if re.skipMetricOnError {
					slog.Error("Error while evaluating metric. Skipping metric", "metric_name", metric.GetName(), "metric_id", metric.GetId(), "error", err)
					continue
				} else {
					re.mrtc.m[key] = nil
					re.mrtc.Unlock()
					return nil, err
				}
			}

			if runMap != nil {
				cached = append(cached, metric)
				data = append(data, runMap)
			}
		}

		if re.cacheApplicableMetrics && len(cached) > 0 {
			re.mrtc.m[key] = cached
		}
		slog.Info("Resource type has the applicable metric(s) (HE)", slog.Any("key", key), slog.Any("len", len(cached)), slog.Any("names", namesOf(cached)))

		re.mrtc.Unlock()
	} else {
		for _, metric := range cached {
			runMap, err := re.evalMapHE(ctx, baseDir, ev.GetTargetOfEvaluationId(), metric, m, src)
			if err != nil {
				return nil, err
			}
			if runMap != nil {
				data = append(data, runMap)
			}
		}
	}

	return data, nil
}

// evalMapHE evaluates a given metric against the provided map of encrypted
// resource data. It prepares and executes a Rego query with the fhe_compare
// built-in, which delegates comparisons to the FHE proxy and returns encrypted
// boolean results.
func (re *regoEval) evalMapHE(ctx context.Context, baseDir string, targetID string, metric *assessment.Metric, m map[string]interface{}, src MetricsSource) (result *CombinedResult, err error) {
	var (
		query  *rego.PreparedEvalQuery
		key    string
		pkg    string
		prefix string
		config *assessment.MetricConfiguration
	)

	// Try to fetch the default metric configuration first (the FHE path uses
	// default configurations so the proxy can pre-encrypt target values). If
	// the source does not support default config fetching, fall back to the
	// regular MetricConfiguration method.
	// if dcs, ok := any(src).(DefaultMetricConfigurationSource); ok {
	// 	config, err = dcs.DefaultMetricConfiguration(ctx, metric)
	// } else {
	config, err = src.MetricConfiguration(ctx, targetID, metric)
	// }
	if err != nil {
		return nil, fmt.Errorf("could not fetch metric configuration for metric %s: %w", metric.Name, err)
	}

	key = fmt.Sprintf("%s-%s-%s", metric.Id, targetID, config.Hash())

	query, err = re.qc.Get(key, func(key string) (*rego.PreparedEvalQuery, error) {
		var (
			tx   storage.Transaction
			impl *assessment.MetricImplementation
		)

		bundle := fmt.Sprintf("%s/policies/security-metrics/metrics/%s/%s/", baseDir, metric.Category, metric.Name)
		operatorsHE := fmt.Sprintf("%s/policies/operators_he.rego", baseDir)

		data := map[string]interface{}{
			"target_value": config.TargetValue.AsInterface(),
			"operator":     config.Operator,
			"config":       config,
		}

		store := inmem.NewFromObject(data)
		ctx := context.Background()

		tx, err = store.NewTransaction(ctx, storage.WriteParams)
		if err != nil {
			return nil, fmt.Errorf("could not create transaction: %w", err)
		}

		prefix = re.pkg
		pkg = util.CamelCaseToSnakeCase(metric.Name)

		impl, err = src.MetricImplementation(ctx, assessment.MetricImplementation_LANGUAGE_REGO, metric)
		if err != nil {
			return nil, fmt.Errorf("could not fetch policy for metric %s: %w", metric.Name, err)
		}

		err = store.UpsertPolicy(context.Background(), tx, bundle+"metric.rego", []byte(impl.Code))
		if err != nil {
			return nil, fmt.Errorf("could not upsert policy: %w", err)
		}

		// Register the fhe_compare built-in. It takes 3 arguments:
		//   1. operator (string) — e.g. ">=", "=="
		//   2. value (any) — the encrypted ciphertext string from the evidence
		//   3. target_value (any) — the plaintext target value from the config
		// The built-in derives the ValueType from target_value, base64-decodes
		// the value to bytes, calls the FHE proxy Compare gRPC service, and
		// returns the encrypted boolean result as a base64-encoded string.
		fheCompare := rego.Function3(
			&rego.Function{
				Name:        "fhe_compare",
				Description: "Delegates a comparison to the FHE proxy for homomorphic evaluation, returning an encrypted boolean",
				Decl: types.NewFunction(
					[]types.Type{types.S, types.A, types.A},
					types.S,
				),
				Nondeterministic: true,
			},
			func(bctx rego.BuiltinContext, op1, op2, op3 *ast.Term) (*ast.Term, error) {
				return re.fheCompare(bctx, op1, op2, op3)
			},
		)

		query, err := rego.New(
			rego.Query(fmt.Sprintf(`
			output = data.%s.%s;
			applicable = data.%s.%s.applicable;
			compliant = data.%s.%s.compliant;
			operator = data.cch.operator;
			target_value = data.cch.target_value;
			config = data.cch.config;
			message = object.get(data.%s.%s, "message", "");
			results = object.get(data.%s.%s, "results", [])`, prefix, pkg, prefix, pkg, prefix, pkg, prefix, pkg, prefix, pkg)),
			rego.Package(prefix),
			rego.Store(store),
			rego.Transaction(tx),
			rego.Load(
				[]string{
					operatorsHE,
				},
				nil,
			),
			fheCompare,
			rego.StrictBuiltinErrors(true),
		).PrepareForEval(ctx)
		if err != nil {
			return nil, fmt.Errorf("could not prepare rego evaluation for metric %s: %w", metric.Name, err)
		}

		err = store.Commit(ctx, tx)
		if err != nil {
			return nil, fmt.Errorf("could not commit transaction: %w", err)
		}

		return &query, nil
	})
	if err != nil {
		return nil, fmt.Errorf("could not fetch cached query for metric %s: %w", metric.Name, err)
	}

	results, err := query.Eval(ctx, rego.EvalInput(m))
	if err != nil {
		return nil, fmt.Errorf("could not evaluate rego policy: %w", err)
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("no results. probably the package name of metric %s is wrong", metric.Name)
	}

	result = &CombinedResult{
		Applicable: results[0].Bindings["applicable"].(bool),
		Compliant:  results[0].Bindings["compliant"].(bool),
		MetricID:   metric.Id,
		MetricName: metric.Name,
	}

	if metric.Name == "AdversarialRobustness" {
		slog.Info("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
	}
	result.Config = new(assessment.MetricConfiguration)
	if err = reencode(results[0].Bindings["config"], result.Config); err != nil {
		return nil, err
	}

	if res, ok := results[0].Bindings["results"]; ok {
		result.ComparisonResult = make([]*assessment.ComparisonResult, 0)
		if err = reencode(res, &result.ComparisonResult); err != nil {
			return nil, err
		}
	} else {
		result.ComparisonResult = append(result.ComparisonResult, &assessment.ComparisonResult{
			Property:    pkg,
			Value:       &structpb.Value{},
			Operator:    config.GetOperator(),
			TargetValue: config.GetTargetValue(),
			Success:     result.Compliant,
		})
	}

	if msg, ok := results[0].Bindings["message"]; ok {
		if msg != "" {
			result.Message = fmt.Sprintf("%s %s", msg, assessment.AdditionalDetailsMessage)
		} else {
			result.Message = assessment.AdditionalDetailsMessage
		}
	} else if result.Compliant {
		result.Message = assessment.DefaultCompliantMessage + " " + assessment.AdditionalDetailsMessage
	} else if !result.Compliant {
		result.Message = assessment.DefaultNonCompliantMessage + " " + assessment.AdditionalDetailsMessage
	}

	if !result.Applicable {
		return nil, nil
	} else {
		return result, nil
	}
}

// fheCompare is the implementation of the fhe_compare Rego built-in. It
// derives the ValueType from the target_value term, base64-decodes the
// encrypted value to bytes, calls the FHE proxy Compare gRPC service, and
// returns the encrypted boolean result as a base64-encoded string.
func (re *regoEval) fheCompare(bctx rego.BuiltinContext, operatorTerm, valueTerm, targetValueTerm *ast.Term) (*ast.Term, error) {
	var (
		operatorStr    string
		valueStr       string
		targetValueStr string
		valueType      string
		actualValue    []byte
		err            error
	)

	if re.fheComparer == nil {
		return nil, fmt.Errorf("fhe_compare: no FHE comparer configured")
	}

	// Extract operator (must be a string)
	operatorVal, ok := operatorTerm.Value.(ast.String)
	if !ok {
		return nil, fmt.Errorf("fhe_compare: operator must be a string, got %T", operatorTerm.Value)
	}
	operatorStr = string(operatorVal)

	// Extract value (the ciphertext — should be a base64-encoded string)
	valueVal, ok := valueTerm.Value.(ast.String)
	if !ok {
		return nil, fmt.Errorf("fhe_compare: value must be a base64-encoded ciphertext string, got %T", valueTerm.Value)
	}
	valueStr = string(valueVal)

	// Base64-decode the value to get the raw encrypted bytes
	actualValue, err = base64.StdEncoding.DecodeString(valueStr)
	if err != nil {
		return nil, fmt.Errorf("fhe_compare: could not base64-decode value: %w", err)
	}

	// Derive ValueType and string representation from target_value
	switch tv := targetValueTerm.Value.(type) {
	case ast.Number:
		valueType = "number"
		targetValueStr = string(tv)
	case ast.Boolean:
		valueType = "boolean"
		if bool(tv) {
			targetValueStr = "true"
		} else {
			targetValueStr = "false"
		}
	case ast.String:
		valueType = "string"
		targetValueStr = string(tv)
	default:
		return nil, fmt.Errorf("fhe_compare: unsupported target_value type %T", targetValueTerm.Value)
	}

	// Call the FHE proxy Compare service via the comparer interface
	encryptedResult, err := re.fheComparer.FheCompare(bctx.Context, operatorStr, targetValueStr, actualValue, valueType)
	if err != nil {
		return nil, fmt.Errorf("fhe_compare: FHE proxy compare failed: %w", err)
	}

	// Return the encrypted boolean as a base64-encoded string, so it can be
	// stored in the comparison_result map and re-encoded to bytes in the proto
	// ComparisonResult.encrypted_success field.
	resultStr := base64.StdEncoding.EncodeToString(encryptedResult)

	return ast.StringTerm(resultStr), nil
}

// createKeyFromEncrypted creates a cache key from the encrypted evidence's tool
// ID and resource types, analogous to createKey for plaintext evidence.
func createKeyFromEncrypted(ev *evidence.EvidenceEncrypted, types []string) (key string) {
	key = strings.Join(append(types, ev.ToolId), "-")
	key = strings.ReplaceAll(key, " ", "")
	return
}

// unwrapEncryptedResource flattens the nested resource map produced by
// google.protobuf.Struct.AsMap(). The FHE proxy sends the resource nested
// under its ontology type key (e.g. {"machineLearningModel": {"score": "..."}}),
// but the Rego metrics expect flat access (input.score), matching the
// plaintext ontology.ResourceMap output. If the map has exactly one key
// whose value is itself a map, that inner map is returned. Otherwise the
// map is returned as-is.
func unwrapEncryptedResource(m map[string]any) map[string]any {
	if len(m) == 1 {
		for _, v := range m {
			if inner, ok := v.(map[string]any); ok {
				return inner
			}
		}
	}
	return m
}
