# Example Evidence for `MachineLearningModel``
`
{"evidence":{"id":"744f2c60-ebe1-484b-a33e-9fd5609b47cc","timestamp":"2026-09-22T12:06:17.215737Z","targetOfEvaluationId":"6d4f7c9c-fa41-4fe3-a5d7-a6e165c3e0d8","toolId":"app.telemetry evidence collector","resource":{"machineLearningModel":{"adversarialRobustnessScore":42.42,"creationTime":"2026-10-30T10:37:23.565266Z","description":"dummy","evasionEfficacyLevel":42.42,"explainability":42.42,"explainabilityEnabled":true,"id":"dummy","labels":{"key1":"value1","key2":"value2"},"membershipInferenceResilience":42.42,"modelStealResilience":42.42,"name":"dummy","poisonedDataLevel":42.42,"poisoningResilienceLevel":42.42,"raw":"dummy","dataLocation":{},"parentId":"","vulnerabilities":[{"criticality":"dummy","cve":"dummy","cwe":["dummy1","dummy2"],"description":"dummy","exploitable":true,"url":"dummy"},{"criticality":"dummy","cve":"dummy","cwe":["dummy1","dummy2"],"description":"dummy","exploitable":true,"url":"dummy"}]}}}}
`

grpc call: `grpcurl --plaintext -d '{"evidence":{"id":"744f2c60-ebe1-484b-a33e-9fd5609b47cc","timestamp":"2026-09-22T12:06:17.215737Z","targetOfEvaluationId":"6d4f7c9c-fa41-4fe3-a5d7-a6e165c3e0d8","toolId":"app.telemetry evidence collector","resource":{"machineLearningModel":{"adversarialRobustnessScore":42.42,"creationTime":"2026-10-30T10:37:23.565266Z","description":"dummy","evasionEfficacyLevel":42.42,"explainability":42.42,"explainabilityEnabled":true,"id":"dummy","labels":{"key1":"value1","key2":"value2"},"membershipInferenceResilience":42.42,"modelStealResilience":42.42,"name":"dummy","poisonedDataLevel":42.42,"poisoningResilienceLevel":42.42,"raw":"dummy","dataLocation":{},"parentId":"","vulnerabilities":[{"criticality":"dummy","cve":"dummy","cwe":["dummy1","dummy2"],"description":"dummy","exploitable":true,"url":"dummy"},{"criticality":"dummy","cve":"dummy","cwe":["dummy1","dummy2"],"description":"dummy","exploitable":true,"url":"dummy"}]}}}}'  -H "authorization: Bearer $TOKEN" $DEST confirmate.evidence.v1.EvidenceStore.StoreEvidence`

# Metrics for `MachineLearningModel`
- EvasionAttackEfficacy (62af69a7-8113-49a1-b98a-715b6ec0e6e6)
- AdversarialRobustness (92469698-362f-49b4-a8bb-2be5375fa7b7)
- NoKnownVulnerabilities (92b4404d-0f00-4e9c-9d1c-52cb970d975b)
- DataPoisoningDetected (9d835190-6d28-4871-bbb9-8d5bd21be8c4)
- MachineLearningModelVulnerabilitiesDetected (acba07ce-2001-46b0-aa75-7a3aad92f59b)
- ExplainabilityEnabled (b22bba3e-ba7e-4a3a-b738-6155a6c7469e)
- ModelStealResilience (ba1b63c2-60e2-464a-ba23-624180b8506a)
- PoisoningResilience (c64aad3a-560c-4094-85f0-b77a64ad3f9d)
- VulnerabilitiesNotExploitable (e0f1b6f2-13f5-482e-924e-c9e29145d7e5)
- MembershipInferenceResilience (febb8eae-2dd0-4e08-9428-2f1c00616f86)

