#!/usr/bin/env node
/**
 * Entry point for the Node.js mirror of the n8n workflow.
 *
 *   node src/index.js                      Start the webhook server (POST WEBHOOK_PATH, GET /healthz)
 *   node src/index.js --simulate [files]   Run fixtures end to end with DRY_RUN forced to true
 *   node src/index.js --validate-schema    Check the extraction schema, rules file and n8n workflow
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  createClientsFromConfig,
  createSeenStore,
  loadConfig,
  processWebhook,
  validateConfigForMode,
} from './pipeline.js';
import { validateQualificationRules } from './validators/stageGateValidator.js';
import { isPlaceholder, signWebhookPayload } from './utils/security.js';
import {
  checkStrictSchemaCompatibility,
  EXTRACTION_SCHEMA,
  mockExtractQualification,
  validateExtraction,
} from './extractors/meddicBantExtractor.js';
import { normalizeTranscriptPayload } from './normalizers/transcriptNormalizer.js';

export const ROOT_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const DEFAULT_FIXTURES = ['sample-gong-webhook.json', 'sample-fireflies-webhook.json', 'sample-fathom-webhook.json'].map(
  (name) => path.join(ROOT_DIR, 'fixtures', name),
);
export const WORKFLOW_PATH = path.join(ROOT_DIR, 'workflows', 'n8n-hubspot-post-call-meddic-bant-extractor.json');

/** Minimal .env loader (no dependency). Existing environment variables always win. */
export function loadDotEnvFile(filePath = path.join(ROOT_DIR, '.env'), target = process.env) {
  if (!fs.existsSync(filePath)) return false;
  for (const line of fs.readFileSync(filePath, 'utf8').split(/\r?\n/)) {
    const match = line.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
    if (!match) continue;
    const [, key, rawValue] = match;
    let value = rawValue;
    if (/^(['"]).*\1$/.test(value)) value = value.slice(1, -1);
    else value = value.replace(/\s+#.*$/, '');
    if (target[key] === undefined) target[key] = value;
  }
  return true;
}

export function loadQualificationRules(env = process.env) {
  let rules;
  let source;
  if (env.QUALIFICATION_RULES_JSON) {
    rules = JSON.parse(env.QUALIFICATION_RULES_JSON);
    source = 'QUALIFICATION_RULES_JSON';
  } else {
    const local = path.join(ROOT_DIR, 'config', 'qualification-rules.local.json');
    const example = path.join(ROOT_DIR, 'config', 'qualification-rules.example.json');
    const chosen = env.QUALIFICATION_RULES_PATH
      ? path.resolve(ROOT_DIR, env.QUALIFICATION_RULES_PATH)
      : fs.existsSync(local)
        ? local
        : example;
    rules = JSON.parse(fs.readFileSync(chosen, 'utf8'));
    source = path.relative(ROOT_DIR, chosen);
  }
  const check = validateQualificationRules(rules);
  if (!check.valid) throw new Error(`Invalid qualification rules (${source}): ${check.errors.join('; ')}`);
  return { rules, source };
}

const LOG_LEVELS = { debug: 10, info: 20, warn: 30, error: 40 };

export function createLogger(level = 'info') {
  const threshold = LOG_LEVELS[level] ?? LOG_LEVELS.info;
  const write = (lvl, msg, data) => {
    if (LOG_LEVELS[lvl] < threshold) return;
    const line = JSON.stringify({ ts: new Date().toISOString(), level: lvl, msg, ...(data || {}) });
    (lvl === 'error' || lvl === 'warn' ? process.stderr : process.stdout).write(`${line}\n`);
  };
  return {
    debug: (m, d) => write('debug', m, d),
    info: (m, d) => write('info', m, d),
    warn: (m, d) => write('warn', m, d),
    error: (m, d) => write('error', m, d),
  };
}

function readRequestBody(req, maxBytes) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > maxBytes) {
        reject(Object.assign(new Error('payload_too_large'), { statusCode: 413 }));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function sendJson(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': Buffer.byteLength(payload) });
  res.end(payload);
}

export function createWebhookServer({ config, rules, logger = createLogger('info'), fetchImpl = globalThis.fetch, webhookPath = '/webhooks/post-call' }) {
  const seenStore = createSeenStore({});
  const clients = createClientsFromConfig(config, { fetchImpl });
  return http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://localhost');
    try {
      if (req.method === 'GET' && url.pathname === '/healthz') {
        return sendJson(res, 200, { ok: true, dryRun: config.dryRun, sandboxMode: config.sandboxMode, llmProvider: config.llm.provider });
      }
      if (url.pathname !== webhookPath) return sendJson(res, 404, { error: 'not_found' });
      if (req.method !== 'POST') return sendJson(res, 405, { error: 'method_not_allowed' });
      const rawBody = await readRequestBody(req, config.webhook.maxBodyBytes);
      const result = await processWebhook(
        { rawBody, headers: req.headers, query: Object.fromEntries(url.searchParams) },
        { config, rules, fetchImpl, seenStore, clients },
      );
      logger.info('webhook_processed', {
        status: result.body.status,
        reason: result.body.reason,
        source: result.body.source,
        callId: result.body.callId,
        dealId: result.body.deal?.id || null,
        gatePassed: result.body.gate?.passed ?? null,
        score: result.body.score,
      });
      return sendJson(res, result.httpStatus, result.body);
    } catch (err) {
      const status = err.statusCode || 500;
      logger.error('webhook_error', { status, message: err.message });
      return sendJson(res, status, { status: 'failed', reason: status === 413 ? 'payload_too_large' : 'internal_error' });
    }
  });
}

export async function runSimulation(files = DEFAULT_FIXTURES, { env = process.env, fetchImpl = globalThis.fetch, now = Date.now } = {}) {
  // A throwaway secret is generated when none is configured, so signature verification still runs.
  const secret = isPlaceholder(env.WEBHOOK_SIGNING_SECRET) ? crypto.randomBytes(32).toString('hex') : env.WEBHOOK_SIGNING_SECRET;
  const config = loadConfig({ ...env, DRY_RUN: 'true', WEBHOOK_SIGNING_SECRET: secret });
  const { rules } = loadQualificationRules(env);
  const results = [];
  for (const file of files) {
    const rawBody = fs.readFileSync(path.resolve(file), 'utf8');
    const timestamp = String(Math.floor(now() / 1000));
    const headers = {
      [config.webhook.signatureHeader]: signWebhookPayload({ secret: config.webhook.secret, rawBody, timestamp }),
      [config.webhook.timestampHeader]: timestamp,
    };
    const result = await processWebhook({ rawBody, headers, query: {} }, { config, rules, fetchImpl, seenStore: createSeenStore({}), now });
    results.push({ file: path.basename(file), httpStatus: result.httpStatus, ...result.body });
  }
  return results;
}

function printSimulationTable(results) {
  for (const r of results) {
    const issues = (r.gate?.issues || []).map((i) => `${i.field}:${i.reason}`).join(', ') || 'none';
    const lines = [
      `\n▶ ${r.file}  [HTTP ${r.httpStatus}] status=${r.status}${r.reason ? ` reason=${r.reason}` : ''}`,
      `  source=${r.source} callId=${r.callId} dryRun=${r.dryRun} sandboxMode=${r.sandboxMode}`,
      `  deal=${r.deal ? `${r.deal.id} (${r.deal.stage}) via ${r.dealMatch?.matchedBy}` : 'none'}`,
      `  score=${r.score ?? 'n/a'} gate=${r.gate ? (r.gate.evaluated ? (r.gate.passed ? 'PASSED' : 'BLOCKED') : `not evaluated (${r.gate.reason})`) : 'n/a'} target=${r.gate?.targetStageId || 'n/a'}`,
      `  gate issues: ${issues}`,
      `  hubspot: properties=${r.actions?.hubspot?.propertyUpdate?.mode || 'n/a'} (${(r.actions?.hubspot?.propertyUpdate?.written || []).length} fields) note=${r.actions?.hubspot?.note?.mode || 'n/a'}`,
      `  slack: ${r.actions?.slack?.mode || 'n/a'} (${r.actions?.slack?.kind || 'no message'})`,
      `  pii redactions: ${JSON.stringify(r.privacy?.redactions || {})}`,
    ];
    process.stdout.write(`${lines.join('\n')}\n`);
  }
}

/** Structural checks for the exported n8n workflow. Returns a list of errors. */
export function validateWorkflowStructure(workflow) {
  const errors = [];
  if (!Array.isArray(workflow?.nodes) || !workflow.nodes.length) return ['workflow.nodes must be a non-empty array'];
  const names = new Set();
  for (const node of workflow.nodes) {
    if (!node.name || !node.type || node.typeVersion === undefined || !Array.isArray(node.position)) {
      errors.push(`node ${node.name || '(unnamed)'} is missing name/type/typeVersion/position`);
    }
    if (names.has(node.name)) errors.push(`duplicate node name "${node.name}"`);
    names.add(node.name);
  }
  for (const [from, outputs] of Object.entries(workflow.connections || {})) {
    if (!names.has(from)) errors.push(`connection from unknown node "${from}"`);
    for (const branch of outputs.main || []) {
      for (const link of branch || []) if (!names.has(link.node)) errors.push(`connection to unknown node "${link.node}"`);
    }
  }
  const serialized = JSON.stringify(workflow);
  const secretPatterns = [
    /sk-[A-Za-z0-9]{20,}/,
    /pat-(?:na|eu)\d-[0-9a-f-]{20,}/,
    /xox[abpr]-[0-9A-Za-z-]{10,}/,
    /hooks\.slack\.com\/services\/T[0-9A-Z]{6,}/,
  ];
  for (const re of secretPatterns) if (re.test(serialized)) errors.push(`workflow contains a credential-like string matching ${re}`);
  if (workflow.nodes.some((n) => n.credentials && Object.keys(n.credentials).length)) {
    errors.push('workflow nodes must not reference stored n8n credentials; use $env variables');
  }
  return errors;
}

export async function runSchemaValidation({ log = (m) => process.stdout.write(`${m}\n`) } = {}) {
  const failures = [];
  const check = (label, errors) => {
    if (errors.length) {
      failures.push(...errors.map((e) => `${label}: ${e}`));
      log(`✗ ${label}`);
      errors.forEach((e) => log(`    ${e}`));
    } else {
      log(`✓ ${label}`);
    }
  };
  check('Extraction schema is strict-mode compatible', checkStrictSchemaCompatibility(EXTRACTION_SCHEMA));
  const fixtureErrors = [];
  for (const file of DEFAULT_FIXTURES) {
    const normalized = normalizeTranscriptPayload(JSON.parse(fs.readFileSync(file, 'utf8')), { internalDomains: ['example.com'] });
    const result = validateExtraction(mockExtractQualification(normalized, normalized.transcript), { transcriptText: normalized.transcript });
    if (!result.valid) fixtureErrors.push(`${path.basename(file)}: ${result.errors.join('; ')}`);
  }
  check('Fixture extractions validate against the schema', fixtureErrors);
  const ruleFiles = ['qualification-rules.example.json', 'qualification-rules.local.json']
    .map((f) => path.join(ROOT_DIR, 'config', f))
    .filter((f) => fs.existsSync(f));
  for (const file of ruleFiles) {
    check(`Rules file ${path.relative(ROOT_DIR, file)}`, validateQualificationRules(JSON.parse(fs.readFileSync(file, 'utf8'))).errors);
  }
  let workflow = null;
  try {
    workflow = JSON.parse(fs.readFileSync(WORKFLOW_PATH, 'utf8'));
    check('n8n workflow structure and credential scan', validateWorkflowStructure(workflow));
  } catch (err) {
    check('n8n workflow parses as JSON', [err.message]);
  }
  if (workflow) {
    const { buildWorkflow, serializeWorkflow } = await import(pathToFileURL(path.join(ROOT_DIR, 'scripts', 'build-n8n-workflow.js')).href);
    const expected = serializeWorkflow(buildWorkflow());
    const actual = fs.readFileSync(WORKFLOW_PATH, 'utf8');
    check('n8n workflow is in sync with src/ (run npm run build:workflow if not)', expected === actual ? [] : ['workflow JSON differs from a fresh build']);
  }
  return { ok: failures.length === 0, failures };
}

async function main(argv) {
  loadDotEnvFile();
  const logger = createLogger(process.env.LOG_LEVEL || 'info');
  if (argv.includes('--validate-schema')) {
    const { ok } = await runSchemaValidation();
    process.exitCode = ok ? 0 : 1;
    return;
  }
  if (argv.includes('--simulate')) {
    const files = argv.filter((a) => !a.startsWith('--'));
    const results = await runSimulation(files.length ? files : DEFAULT_FIXTURES);
    if (argv.includes('--json')) process.stdout.write(`${JSON.stringify(results, null, 2)}\n`);
    else printSimulationTable(results);
    process.stdout.write('\nSimulation ran with DRY_RUN forced to true. No HubSpot or Slack mutations were sent.\n');
    return;
  }
  const config = loadConfig(process.env);
  const { errors, warnings } = validateConfigForMode(config);
  warnings.forEach((w) => logger.warn('config_warning', { warning: w }));
  if (errors.length) {
    errors.forEach((e) => logger.error('config_error', { error: e }));
    process.exitCode = 1;
    return;
  }
  const { rules, source } = loadQualificationRules(process.env);
  const port = Number(process.env.PORT) || 3000;
  const webhookPath = process.env.WEBHOOK_PATH || '/webhooks/post-call';
  const server = createWebhookServer({ config, rules, logger, webhookPath });
  server.requestTimeout = 120000;
  server.listen(port, () => {
    logger.info('server_started', {
      port,
      webhookPath,
      dryRun: config.dryRun,
      sandboxMode: config.sandboxMode,
      llmProvider: config.llm.provider,
      rules: source,
    });
  });
  const shutdown = () => server.close(() => process.exit(0));
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

const invokedDirectly = process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (invokedDirectly) {
  main(process.argv.slice(2)).catch((err) => {
    process.stderr.write(`${err.stack || err.message}\n`);
    process.exitCode = 1;
  });
}
