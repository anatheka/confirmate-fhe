package cch
import rego.v1

# operators_he.rego is the FHE (Fully Homomorphic Encryption) variant of
# operators.rego. It provides the same comparison_result(property, value)
# interface that 100+ metric .rego files import as data.cch.comparison_result,
# but instead of comparing plaintext values in Rego, it delegates each
# comparison to the fhe_compare built-in. The built-in sends the encrypted
# value and plaintext target_value to the FHE proxy for homomorphic evaluation.

# operator and target_value are declared here to add them to the output of each single policy (so assessment can use it)
operator = data.operator

target_value = data.target_value

# we also expose the whole metric configuration as well.
config = data.config

# fhe_compare is a custom OPA built-in (registered in Go via rego.Function3).
# It takes (operator, value, target_value), derives the datatype from
# target_value, and sends an HTTP POST to the FHE proxy Compare endpoint.
# The proxy performs the homomorphic comparison and returns a boolean.
#
# In the HE path, `value` is a base64-encoded FHE ciphertext string (from the
# encrypted evidence resource), while `target_value` is the plaintext
# configuration value (number, boolean, or string).

# compare delegates to fhe_compare for the HE path. This exists so that
# metrics importing data.cch.compare can be loaded; for metrics applicable
# to encrypted resources, the comparison goes through fhe_compare.
compare(operator, target_value, actual_value) := x if {
	x := fhe_compare(operator, actual_value, target_value)
}

# Builds a single comparison-result object in the shape Go's evalMapHE()
# expects for assessment.ComparisonResult (property/value/target_value/
# operator/success), using fhe_compare instead of plaintext compare().
comparison_result(property, value) := {
	"property": property,
	"value": value,
	"target_value": data.cch.target_value,
	"operator": data.cch.operator,
	"success": fhe_compare(data.cch.operator, value, data.cch.target_value),
}
