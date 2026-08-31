# AWS code-to-cloud live acceptance — 2026-08-31

## Result

The AWS deployment inventory slice passed live provider acceptance against account
`331145994818` in selected Region `ap-south-1` using local AWS profile `sara-sales`.

The dedicated `DenaliCodeToCloudAcceptanceRole` passed exact account binding, enabled-Region
discovery, and the Lambda, ECS, EKS, and SageMaker validation entrypoints. Collection then
completed all eight service inventory/relationship planes without a failed or partial plane.

## Accepted boundary

| Field | Value |
| --- | --- |
| AWS account | `331145994818` |
| Selected Region | `ap-south-1` |
| Enabled Regions discovered | 17 |
| Regions outside selected scope | 16 |
| Denali connection | `fd48da13-ed53-43d9-b832-af7cdae48aa4` |
| Role | `DenaliCodeToCloudAcceptanceRole` |
| CloudFormation stack | `denali-code-to-cloud-acceptance` |

The connection declared only `aws.code_to_cloud`. No broader Denali scope was implied by the
profile used to create the read-only role.

## Live collection evidence

| Service | Observed | Classified AI workloads |
| --- | ---: | ---: |
| Lambda | 2 | 1 |
| ECS task-definition families | 1 | 1 |
| EKS | 0 | 0 |
| SageMaker endpoints | 0 | 0 |

The run ingested seven assertions and two AI workloads. Lambda `ni-sales-agent` was
classified from the `BEDROCK_MODEL_ID` and `REVIEWER_MODEL_ID` configuration **keys**.
Lambda `ni-sales-render` remained an ordinary cloud resource. ECS family
`NiSalesAgentStackProposalWorkerTaskC2F0F9A1` revision 20 was classified from its model
configuration keys. Environment values were not retained.

Successful empty EKS and SageMaker planes prove only that the bounded list operations
completed in the selected Region. They do not claim that those resource types exist or are
safe.

## Compatibility evidence

The existing CDK Lambda/ECS correlation remained reportable after direct account inventory
was ingested. The legacy CDK contract still requires CloudFormation logical-ID evidence plus
the exact function or container name; the new account/Region/name observations coexist with
it and do not relax it.

## Execution boundary

The standard local API container intentionally does not mount workstation AWS credentials.
For this acceptance only, a temporary API container mounted the local AWS configuration
read-only, selected `AWS_PROFILE=sara-sales`, and exposed port 8089. No profile content or
temporary AWS credential was copied into the repository, database, evidence, or container
image. The temporary container was removed after the run.

## Browser review

The persisted connection can be reviewed in the standard web application. Confirm that:

1. `Sara Sales AWS Code-to-Cloud Acceptance` is healthy.
2. The exact account is `331145994818` and the selected Region is `ap-south-1`.
3. Credential/account binding plus all four deployment validation checks passed.
4. Sixteen discovered Regions are visibly outside the selected collection scope.

The one-run collection summary was process-local to the temporary acceptance API; the
persisted inventory and correlation reports remain available through the normal API.

## Verification gates

- Live credential and exact-account validation: passed.
- Enabled-Region discovery and selected-scope enforcement: passed.
- Lambda, ECS, EKS, and SageMaker validation: passed.
- Eight independent collection planes: complete.
- Existing CDK correlation compatibility: passed.

## Exact teardown

The read-only role stack is intentionally retained until manual browser review is complete.
Remove only this acceptance stack afterward:

```bash
AWS_PROFILE=sara-sales aws cloudformation delete-stack \
  --stack-name denali-code-to-cloud-acceptance \
  --region ap-south-1

AWS_PROFILE=sara-sales aws cloudformation wait stack-delete-complete \
  --stack-name denali-code-to-cloud-acceptance \
  --region ap-south-1
```

Then disable and delete the named acceptance connection from Denali. The pre-existing
`DenaliSecurityAuditRole` was not changed by this acceptance.
