package cch
import rego.v1

# operators_he.rego is the FHE (Fully Homomorphic Encryption) variant of
# operators.rego in `policies/security-metrics/`. It provides the same comparison_result(property, value)
# interface that .rego files import as data.cch.comparison_result,
# but instead of comparing plaintext values in Rego, it delegates each
# comparison to the fhe_compare built-in.
#
# In the HE path:
# - success is always false because the encrypted boolean result cannot be
#   evaluated in Rego's boolean logic.
# - encrypted_success holds the base64-encoded serialized FheBool result from
#   the FHE proxy Compare service.
# - compliant is always false (derived from success via "every r in results
#   { r.success }" in each metric .rego file).

# operator and target_value are declared here to add them to the output of each single policy (so assessment can use it)
operator = data.operator
target_value = data.target_value

# we also expose the whole metric configuration as well.
config = data.config

# compare delegates to fhe_compare for the HE path. Returns false (cannot be
# computed) so that metrics using compare() directly in if-conditions are
# non-compliant. The encrypted result is only captured via comparison_result.
compare(operator, target_value, actual_value) := false

# Builds a single comparison-result object in the shape Go's evalMapHE()
# expects for assessment.ComparisonResult (property/value/target_value/
# operator/success/encrypted_success), using fhe_compare instead of plaintext
# compare().
comparison_result(property, value) := {
	"property": property,
	"value": value,
	"target_value": data.cch.target_value,
	"operator": data.cch.operator,
	"success": false,
	"encrypted_success": fhe_compare(data.cch.operator, value, data.cch.target_value),
}
