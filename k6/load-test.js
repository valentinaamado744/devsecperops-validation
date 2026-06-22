// Prueba de carga y estrés con k6 - modelo DevSecPerOps
// Materializa el Performance Gate: si el p(95) de tiempo de respuesta supera el
// umbral o la tasa de error es alta, k6 termina con código != 0 y el pipeline falla.

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

const errorRate = new Rate('errors');
const reportLatency = new Trend('report_latency', true);

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8000';

export const options = {
  stages: [
    { duration: '30s', target: 10 },  // rampa de subida
    { duration: '1m', target: 25 },   // carga sostenida
    { duration: '30s', target: 0 },   // rampa de bajada
  ],
  thresholds: {
    // PERFORMANCE GATE: p(95) por debajo de 500 ms y menos del 1 % de errores
    http_req_duration: ['p(95)<500'],
    errors: ['rate<0.01'],
  },
};

export default function () {
  // Endpoint sano
  const health = http.get(`${BASE_URL}/health`);
  check(health, { 'health 200': (r) => r.status === 200 }) || errorRate.add(1);

  // Endpoint deliberadamente lento (defecto de rendimiento sembrado)
  const report = http.get(`${BASE_URL}/reports`);
  reportLatency.add(report.timings.duration);
  check(report, { 'reports 200': (r) => r.status === 200 }) || errorRate.add(1);

  sleep(1);
}
