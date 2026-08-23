import http from "k6/http";
import exec from "k6/execution";
import { check, fail, sleep } from "k6";
import { Counter, Rate, Trend } from "k6/metrics";

const BASE_URL = (__ENV.KCSP_BASE_URL || "http://api:8080").replace(/\/$/, "");
const TENANT_ID = __ENV.KCSP_TENANT_ID || "university-kulazhanov";
const COLLECTOR_TOKEN = __ENV.KCSP_COLLECTOR_TOKEN || "kcsp-demo-collector";
const ANALYST_TOKEN = __ENV.KCSP_ANALYST_TOKEN || "kcsp-demo-l2";
const PROFILE = __ENV.KCSP_LOAD_PROFILE || "smoke";
const SKIP_VISIBILITY = (__ENV.KCSP_SKIP_VISIBILITY || "false") === "true";
const ALLOW_DEMO_CREDENTIALS = (__ENV.KCSP_ALLOW_DEMO_CREDENTIALS || "false") === "true";
const SUMMARY_PATH = __ENV.KCSP_SUMMARY_PATH || "/tmp/kcsp-load-summary.json";

const eventsAccepted = new Counter("events_accepted");
const ingestErrors = new Rate("ingest_errors");
const readErrors = new Rate("read_errors");
const pipelineVisibility = new Trend("pipeline_visibility_ms", true);
const pipelineVisibilityFailures = new Rate("pipeline_visibility_failures");

function numberEnv(name, fallback) {
  const value = Number(__ENV[name]);
  return Number.isFinite(value) && value > 0 ? value : fallback;
}

function durationEnv(name, fallback) {
  const value = String(__ENV[name] || "").trim();
  return value || fallback;
}

function constantArrival(rate, duration) {
  return {
    executor: "constant-arrival-rate",
    exec: "ingestEvent",
    rate,
    timeUnit: "1s",
    duration,
    preAllocatedVUs: Math.max(2, Math.ceil(rate / 5)),
    maxVUs: Math.max(10, Math.ceil(rate * 2)),
    gracefulStop: "30s",
    tags: { workload: "ingest" },
  };
}

function scenarios() {
  const rate = numberEnv("KCSP_INGEST_RATE", PROFILE === "sustained" ? 250 : PROFILE === "fault" ? 20 : 5);
  const duration = durationEnv(
    "KCSP_LOAD_DURATION",
    PROFILE === "sustained" ? "15m" : PROFILE === "fault" ? "15s" : "15s",
  );
  if (PROFILE === "spike") {
    return {
      ingest: {
        executor: "ramping-arrival-rate",
        exec: "ingestEvent",
        startRate: Math.max(1, Math.floor(rate / 5)),
        timeUnit: "1s",
        preAllocatedVUs: Math.max(20, Math.ceil(rate / 2)),
        maxVUs: Math.max(100, Math.ceil(rate * 2)),
        stages: [
          { duration: "30s", target: rate },
          { duration: "30s", target: rate * 4 },
          { duration: "1m", target: rate * 4 },
          { duration: "30s", target: rate },
        ],
        gracefulStop: "30s",
        tags: { workload: "ingest" },
      },
      read: {
        executor: "constant-vus",
        exec: "readSOC",
        vus: numberEnv("KCSP_READ_VUS", 5),
        duration: "2m30s",
        gracefulStop: "15s",
        tags: { workload: "read" },
      },
    };
  }
  const result = { ingest: constantArrival(rate, duration) };
  if (PROFILE !== "fault") {
    result.read = {
      executor: "constant-vus",
      exec: "readSOC",
      vus: numberEnv("KCSP_READ_VUS", PROFILE === "sustained" ? 10 : 2),
      duration,
      gracefulStop: "15s",
      tags: { workload: "read" },
    };
  }
  return result;
}

const thresholds = {
  checks: ["rate>0.99"],
  "http_req_failed{endpoint:ingest}": ["rate<0.01"],
  "http_req_duration{endpoint:ingest}": [
    `p(95)<${numberEnv("KCSP_INGEST_P95_MS", 250)}`,
    `p(99)<${numberEnv("KCSP_INGEST_P99_MS", 750)}`,
  ],
  ingest_errors: ["rate<0.01"],
  dropped_iterations: ["count==0"],
};
if (PROFILE !== "fault") {
  thresholds["http_req_failed{endpoint:read}"] = ["rate<0.01"];
  thresholds["http_req_duration{endpoint:read}"] = [
    `p(95)<${numberEnv("KCSP_READ_P95_MS", 500)}`,
    `p(99)<${numberEnv("KCSP_READ_P99_MS", 1500)}`,
  ];
  thresholds.read_errors = ["rate<0.01"];
}
if (!SKIP_VISIBILITY) {
  thresholds.pipeline_visibility_ms = [`p(95)<${numberEnv("KCSP_PIPELINE_VISIBILITY_SLO_MS", 30000)}`];
  thresholds.pipeline_visibility_failures = ["rate==0"];
}

export const options = {
  scenarios: scenarios(),
  thresholds,
  discardResponseBodies: false,
  userAgent: "kcsp-load-acceptance/1.0",
  summaryTrendStats: ["avg", "min", "med", "p(90)", "p(95)", "p(99)", "max"],
};

const collectorHeaders = {
  Authorization: `Bearer ${COLLECTOR_TOKEN}`,
  "Content-Type": "application/json",
  "X-KCSP-Tenant-ID": TENANT_ID,
  "X-KCSP-Event-Format": "ocsf-json-v1",
};
const analystHeaders = {
  Authorization: `Bearer ${ANALYST_TOKEN}`,
  Accept: "application/json",
  "X-KCSP-Tenant-ID": TENANT_ID,
};
const readEndpoints = [
  "/api/v1/overview",
  "/api/v1/events?limit=50",
  "/api/v1/alerts?limit=50",
  "/api/v1/incidents?limit=50",
];

function eventPayload(eventID) {
  return JSON.stringify({
    event_id: eventID,
    event_time: new Date().toISOString(),
    category: "network_activity",
    activity_name: "KCSP load acceptance event",
    severity_id: 1,
    source: {
      vendor: "KCSP",
      product: "LoadHarness",
      type: "synthetic",
    },
    device: {
      hostname: `load-${exec.vu.idInTest || 0}`,
      criticality: 1,
    },
    src_endpoint: {
      ip: `198.51.100.${(exec.vu.idInTest % 200) + 1}`,
      port: 49152,
    },
    dst_endpoint: {
      ip: "203.0.113.10",
      port: 443,
    },
    metadata: {
      load_profile: PROFILE,
    },
  });
}

function queue(eventID, tags = {}) {
  const response = http.post(`${BASE_URL}/api/v1/ingest/events`, eventPayload(eventID), {
    headers: collectorHeaders,
    tags: { endpoint: "ingest", ...tags },
    timeout: "10s",
  });
  let receipt;
  try {
    receipt = response.json();
  } catch {
    receipt = {};
  }
  const accepted = check(response, {
    "ingest accepted": (value) => value.status === 202,
    "queue receipt returned": () => receipt?.status === "QUEUED" && Boolean(receipt?.message_id),
  });
  ingestErrors.add(!accepted);
  if (accepted) eventsAccepted.add(1);
  return accepted;
}

export function setup() {
  const usesDemo = COLLECTOR_TOKEN.startsWith("kcsp-demo-") || ANALYST_TOKEN.startsWith("kcsp-demo-");
  if (usesDemo && !ALLOW_DEMO_CREDENTIALS) {
    fail("Demo credentials require KCSP_ALLOW_DEMO_CREDENTIALS=true and must never target production.");
  }
  const ready = http.get(`${BASE_URL}/health/ready`, {
    tags: { endpoint: "preflight" },
    timeout: "10s",
  });
  if (!check(ready, { "API ready": (value) => value.status === 200 })) {
    fail(`API readiness failed with HTTP ${ready.status}`);
  }
  const session = http.get(`${BASE_URL}/api/v1/session`, {
    headers: analystHeaders,
    tags: { endpoint: "preflight" },
    timeout: "10s",
  });
  if (!check(session, { "analyst authenticated": (value) => value.status === 200 })) {
    fail(`Analyst preflight failed with HTTP ${session.status}`);
  }
  const runID = (__ENV.KCSP_RUN_ID || `kcsp-load-${Date.now()}`).replace(/[^a-zA-Z0-9_.-]/g, "-");
  const eventID = `${runID}-setup`;
  const acceptedAt = Date.now();
  if (!queue(eventID, { phase: "setup" })) {
    fail("Collector preflight was not accepted.");
  }
  return { runID, eventID, acceptedAt };
}

export function ingestEvent(data) {
  const eventID = [
    data.runID,
    exec.scenario.name,
    exec.vu.idInTest,
    exec.scenario.iterationInTest,
  ].join("-");
  queue(eventID, { phase: "load" });
}

export function readSOC() {
  const index = Number(exec.scenario.iterationInTest % readEndpoints.length);
  const path = readEndpoints[index];
  const response = http.get(`${BASE_URL}${path}`, {
    headers: analystHeaders,
    tags: { endpoint: "read", resource: path.split("?")[0] },
    timeout: "15s",
  });
  const succeeded = check(response, {
    "SOC read succeeded": (value) => value.status === 200,
  });
  readErrors.add(!succeeded);
  sleep(0.2);
}

export function teardown(data) {
  if (SKIP_VISIBILITY) return;
  const timeoutMs = numberEnv("KCSP_PIPELINE_VISIBILITY_TIMEOUT_MS", 30000);
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const response = http.get(`${BASE_URL}/api/v1/events/${encodeURIComponent(data.eventID)}`, {
      headers: analystHeaders,
      tags: { endpoint: "visibility" },
      timeout: "10s",
    });
    if (response.status === 200) {
      pipelineVisibility.add(Date.now() - data.acceptedAt);
      pipelineVisibilityFailures.add(false);
      return;
    }
    sleep(0.5);
  }
  pipelineVisibilityFailures.add(true);
  fail(`Event ${data.eventID} was not visible within ${timeoutMs}ms.`);
}

function metric(data, name, key) {
  return data.metrics?.[name]?.values?.[key] ?? null;
}

export function handleSummary(data) {
  const report = {
    schema: "kcsp.load-summary/v1",
    profile: PROFILE,
    events_accepted: metric(data, "events_accepted", "count"),
    dropped_iterations: metric(data, "dropped_iterations", "count"),
    ingest_error_rate: metric(data, "ingest_errors", "rate"),
    ingest_p95_ms: metric(data, "http_req_duration{endpoint:ingest}", "p(95)"),
    ingest_p99_ms: metric(data, "http_req_duration{endpoint:ingest}", "p(99)"),
    read_error_rate: metric(data, "read_errors", "rate"),
    read_p95_ms: metric(data, "http_req_duration{endpoint:read}", "p(95)"),
    pipeline_visibility_p95_ms: metric(data, "pipeline_visibility_ms", "p(95)"),
  };
  return {
    stdout: `${JSON.stringify(report)}\n`,
    [SUMMARY_PATH]: JSON.stringify(data, null, 2),
  };
}
