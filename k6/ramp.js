// Capacity calibration: ramp the arrival rate linearly and find the knee offline
// (analysis/knee.py reads the --out csv time series).
import http from 'k6/http';

const GATEWAY = __ENV.GATEWAY_URL || 'http://127.0.0.1:8100';
const CHAIN = __ENV.CHAIN || 'c3';
const MAX_RATE = parseInt(__ENV.MAX_RATE || '2000');
const RAMP = parseInt(__ENV.RAMP || '300');
const TOKEN = __ENV.TOKEN || '';

export const options = {
  scenarios: { ramp: { executor: 'ramping-arrival-rate', startRate: 10, timeUnit: '1s', preAllocatedVUs: 300, maxVUs: parseInt(__ENV.MAX_VUS || "5000"),
    stages: [{ target: MAX_RATE, duration: `${RAMP}s` }] } },
  discardResponseBodies: true,
};

export default function () {
  http.get(`${GATEWAY}/${CHAIN}`, { headers: TOKEN ? { Authorization: `Bearer ${TOKEN}` } : {} });
}
