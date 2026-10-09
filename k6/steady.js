// Open-model load (constant arrival rate) with a discarded warm-up phase.
// Closed-loop fixed-VU tests (Article 1) couple offered load to latency and measure queueing;
// an arrival-rate generator keeps offered load fixed, so latency differences reflect service cost.
import http from 'k6/http';

const GATEWAY = __ENV.GATEWAY_URL || 'http://127.0.0.1:8100';
const CHAIN = __ENV.CHAIN || 'c3';
const RATE = parseInt(__ENV.RATE || '100');
const WARMUP = parseInt(__ENV.WARMUP || '30');
const DURATION = parseInt(__ENV.DURATION || '90');
const TOKEN = __ENV.TOKEN || '';
const PRE_VUS = parseInt(__ENV.PRE_VUS || '200');
const MAX_VUS = parseInt(__ENV.MAX_VUS || '2000');

const scenarios = {};
if (WARMUP > 0) {
  scenarios.warmup = { executor: 'constant-arrival-rate', rate: RATE, timeUnit: '1s', duration: `${WARMUP}s`,
    preAllocatedVUs: PRE_VUS, maxVUs: MAX_VUS, exec: 'hit' };
}
scenarios.measure = { executor: 'constant-arrival-rate', rate: RATE, timeUnit: '1s', duration: `${DURATION}s`,
  startTime: `${WARMUP}s`, preAllocatedVUs: PRE_VUS, maxVUs: MAX_VUS, exec: 'hit' };

export const options = {
  scenarios,
  discardResponseBodies: true,
  summaryTrendStats: ['avg', 'min', 'med', 'max', 'p(90)', 'p(95)', 'p(99)'],
  // always-true thresholds force k6 to materialise the per-scenario sub-metrics
  thresholds: {
    'http_req_duration{scenario:measure}': ['max>=0'],
    'http_req_failed{scenario:measure}': ['rate>=0'],
    'http_reqs{scenario:measure}': ['count>=0'],
    'dropped_iterations{scenario:measure}': ['count>=0'],
  },
};

export function hit() {
  const headers = TOKEN ? { Authorization: `Bearer ${TOKEN}` } : {};
  http.get(`${GATEWAY}/${CHAIN}`, { headers });
}

function val(m, name, key) {
  const x = m[name];
  if (!x) return null;
  const v = x.values || x;
  return v[key] === undefined ? null : v[key];
}

export function handleSummary(data) {
  const m = data.metrics;
  const d = 'http_req_duration{scenario:measure}';
  const out = {
    cfg: { gateway: GATEWAY, chain: CHAIN, rate: RATE, warmup: WARMUP, duration: DURATION },
    latency_ms: { avg: val(m, d, 'avg'), min: val(m, d, 'min'), med: val(m, d, 'med'), p90: val(m, d, 'p(90)'),
      p95: val(m, d, 'p(95)'), p99: val(m, d, 'p(99)'), max: val(m, d, 'max') },
    failed_rate: val(m, 'http_req_failed{scenario:measure}', 'rate'),
    requests: val(m, 'http_reqs{scenario:measure}', 'count'),
    dropped_iterations: val(m, 'dropped_iterations{scenario:measure}', 'count') || 0,
  };
  const res = { stdout: `rate=${RATE} p95=${out.latency_ms.p95} failed=${out.failed_rate} dropped=${out.dropped_iterations}\n` };
  if (__ENV.SUMMARY_PATH) res[__ENV.SUMMARY_PATH] = JSON.stringify(out, null, 1);
  return res;
}
