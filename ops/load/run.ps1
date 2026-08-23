[CmdletBinding()]
param(
    [ValidateSet("smoke", "sustained", "spike", "capacity10k", "fault")]
    [string]$Profile = "smoke",
    [string]$DockerNetwork = "kcsp_default",
    [string]$ResultsDirectory = ""
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
if (-not $ResultsDirectory) {
    $ResultsDirectory = Join-Path $root ".artifacts\load"
}
New-Item -ItemType Directory -Force -Path $ResultsDirectory | Out-Null

$image = if ($env:KCSP_K6_IMAGE) {
    $env:KCSP_K6_IMAGE
} else {
    "grafana/k6:2.1.0@sha256:65c920dc067d5e2e00befbf982af6ad6ad0117034e8b1c65817c7975c52d4669"
}
$env:KCSP_LOAD_PROFILE = $Profile
$env:KCSP_BASE_URL = if ($env:KCSP_BASE_URL) { $env:KCSP_BASE_URL } else { "http://api:8080" }
$env:KCSP_TENANT_ID = if ($env:KCSP_TENANT_ID) { $env:KCSP_TENANT_ID } else { "university-kulazhanov" }
$env:KCSP_COLLECTOR_TOKEN = if ($env:KCSP_COLLECTOR_TOKEN) { $env:KCSP_COLLECTOR_TOKEN } else { "kcsp-demo-collector" }
$env:KCSP_ANALYST_TOKEN = if ($env:KCSP_ANALYST_TOKEN) { $env:KCSP_ANALYST_TOKEN } else { "kcsp-demo-l2" }
$env:KCSP_ALLOW_DEMO_CREDENTIALS = if ($env:KCSP_ALLOW_DEMO_CREDENTIALS) { $env:KCSP_ALLOW_DEMO_CREDENTIALS } else { "true" }
$env:KCSP_RUN_ID = if ($env:KCSP_RUN_ID) { $env:KCSP_RUN_ID } else { "kcsp-$Profile-$([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ'))" }
$env:KCSP_SUMMARY_PATH = "/results/kcsp-$Profile-summary.json"

$environmentNames = @(
    "KCSP_BASE_URL",
    "KCSP_TENANT_ID",
    "KCSP_COLLECTOR_TOKEN",
    "KCSP_ANALYST_TOKEN",
    "KCSP_ALLOW_DEMO_CREDENTIALS",
    "KCSP_LOAD_PROFILE",
    "KCSP_LOAD_DURATION",
    "KCSP_INGEST_RATE",
    "KCSP_READ_VUS",
    "KCSP_ASSET_CARDINALITY",
    "KCSP_INGEST_P95_MS",
    "KCSP_INGEST_P99_MS",
    "KCSP_READ_P95_MS",
    "KCSP_READ_P99_MS",
    "KCSP_PIPELINE_VISIBILITY_SLO_MS",
    "KCSP_PIPELINE_VISIBILITY_TIMEOUT_MS",
    "KCSP_SKIP_VISIBILITY",
    "KCSP_RUN_ID",
    "KCSP_SUMMARY_PATH"
)
$arguments = @(
    "run", "--rm",
    "--network", $DockerNetwork,
    "-v", "$root/test/load/k6:/scripts:ro",
    "-v", "$($ResultsDirectory):/results"
)
foreach ($name in $environmentNames) {
    $arguments += @("-e", $name)
}
$arguments += @($image, "run", "/scripts/kcsp.js")

& docker @arguments
if ($LASTEXITCODE -ne 0) {
    throw "KCSP load profile '$Profile' failed with exit code $LASTEXITCODE"
}
