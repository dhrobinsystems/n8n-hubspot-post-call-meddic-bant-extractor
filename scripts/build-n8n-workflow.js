#!/usr/bin/env node
/**
 * Generates workflows/n8n-hubspot-post-call-meddic-bant-extractor.json from src/.
 *
 * Every Code node embeds the same library modules the Node.js mirror imports
 * (imports and `export` keywords stripped), followed by a few lines that call one
 * pipeline stage. That is how the workflow and src/ stay logically identical:
 * the test suite rebuilds the workflow and fails if the committed JSON drifts.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const OUTPUT_PATH = path.join(ROOT, 'workflows', 'n8n-hubspot-post-call-meddic-bant-extractor.json');

export const LIBRARY_MODULES = [
  'src/utils/security.js',
  'src/normalizers/transcriptNormalizer.js',
  'src/extractors/meddicBantExtractor.js',
  'src/validators/stageGateValidator.js',
  'src/services/hubspotClient.js',
  'src/services/slackNotifier.js',
  'src/pipeline.js',
];

const PRELUDE_NAMES = ['env', 'config', 'rules', 'n8nHelpers', 'n8nSleep', 'n8nFetch', 'staticData', 'seenStore', 'clients', 'ctx'];
const TOP_LEVEL_DECL = /^(?:async\s+)?(?:function\*?|const|let|var|class)\s+([A-Za-z_$][\w$]*)/gm;

function stripModuleSyntax(source, file) {
  const withoutImports = source.replace(/^import\s[\s\S]*?from\s+['"][^'"]+['"];\s*$/gm, '');
  if (/^import\s/m.test(withoutImports)) throw new Error(`${file}: unsupported import statement`);
  const withoutExports = withoutImports.replace(/^export\s+(?=(?:async\s+)?(?:function|const|let|class)\s)/gm, '');
  if (/^export\s/m.test(withoutExports)) throw new Error(`${file}: unsupported export statement`);
  return withoutExports.replace(/\n{3,}/g, '\n\n').trim();
}

export function buildLibrarySource(root = ROOT) {
  const seen = new Map(PRELUDE_NAMES.map((n) => [n, 'n8n prelude']));
  seen.set('crypto', 'require prelude');
  seen.set('EMBEDDED_QUALIFICATION_RULES', 'build script');
  const parts = [];
  for (const rel of LIBRARY_MODULES) {
    const body = stripModuleSyntax(fs.readFileSync(path.join(root, rel), 'utf8'), rel);
    for (const match of body.matchAll(TOP_LEVEL_DECL)) {
      if (seen.has(match[1])) throw new Error(`Top-level name "${match[1]}" in ${rel} collides with ${seen.get(match[1])}`);
      seen.set(match[1], rel);
    }
    parts.push(`// ---- ${rel} ----\n${body}`);
  }
  return parts.join('\n\n');
}

const PRELUDE = `
const env = $env;
const config = loadConfig(env);
const rules = env.QUALIFICATION_RULES_JSON ? JSON.parse(env.QUALIFICATION_RULES_JSON) : EMBEDDED_QUALIFICATION_RULES;
const n8nHelpers = this.helpers;
const n8nSleep = (ms) => new Promise((resolve) => (typeof setTimeout === 'function' ? setTimeout(resolve, ms) : resolve()));
const n8nFetch = async (url, init = {}) => {
  const response = await n8nHelpers.httpRequest({
    url,
    method: init.method || 'GET',
    headers: init.headers || {},
    body: init.body,
    json: false,
    returnFullResponse: true,
    ignoreHttpStatusErrors: true,
    timeout: config.llm.timeoutMs,
  });
  const raw = response.body;
  const bodyText = typeof raw === 'string' ? raw : Buffer.isBuffer(raw) ? raw.toString('utf8') : raw == null ? '' : JSON.stringify(raw);
  const headerMap = response.headers || {};
  return {
    ok: response.statusCode >= 200 && response.statusCode < 300,
    status: response.statusCode,
    headers: { get: (name) => headerMap[String(name).toLowerCase()] ?? null },
    text: async () => bodyText,
    json: async () => JSON.parse(bodyText),
  };
};
const staticData = $getWorkflowStaticData('global');
if (!staticData.processedCalls) staticData.processedCalls = {};
const seenStore = createSeenStore(staticData.processedCalls);
const clients = createClientsFromConfig(config, { fetchImpl: n8nFetch, sleep: n8nSleep });
`;

const STAGES = [
  {
    name: 'Verify Signature & Normalize',
    body: `const ctx = null;
const webhookItem = $input.first();
let rawBody = '';
if (webhookItem.binary && webhookItem.binary.data) {
  const buffer = await n8nHelpers.getBinaryDataBuffer(0, 'data');
  rawBody = buffer.toString('utf8');
} else if (typeof webhookItem.json.body === 'string') {
  rawBody = webhookItem.json.body;
} else {
  rawBody = JSON.stringify(webhookItem.json.body ?? {});
}
const result = await ingestStage(
  { rawBody, headers: webhookItem.json.headers || {}, query: webhookItem.json.query || {} },
  { config, seenStore, now: Date.now() },
);
return [{ json: result }];`,
  },
  { name: 'Extract MEDDIC & BANT (LLM)', body: 'const ctx = $input.first().json;\nreturn [{ json: await extractStage(ctx, { config, fetchImpl: n8nFetch }) }];' },
  { name: 'Resolve HubSpot Deal', body: 'const ctx = $input.first().json;\nreturn [{ json: await resolveDealStage(ctx, { config, rules, hubspot: clients.hubspot }) }];' },
  { name: 'Evaluate Stage Gate', body: 'const ctx = $input.first().json;\nreturn [{ json: await gateStage(ctx, { rules }) }];' },
  {
    name: 'Upsert Deal & Log Note',
    body: 'const ctx = $input.first().json;\nreturn [{ json: await writeStage(ctx, { config, rules, hubspot: clients.hubspot, now: Date.now() }) }];',
  },
  { name: 'Slack Gate Alert / Brief', body: 'const ctx = $input.first().json;\nreturn [{ json: await notifyStage(ctx, { config, rules, slack: clients.slack }) }];' },
  { name: 'Finalize Response', body: 'const ctx = $input.first().json;\nreturn [{ json: await finalizeStage(ctx, { seenStore, now: Date.now() }) }];' },
];

const NODE_IDS = [
  '5b0c6a1e-0001-4c3a-9d10-000000000001',
  '5b0c6a1e-0002-4c3a-9d10-000000000002',
  '5b0c6a1e-0003-4c3a-9d10-000000000003',
  '5b0c6a1e-0004-4c3a-9d10-000000000004',
  '5b0c6a1e-0005-4c3a-9d10-000000000005',
  '5b0c6a1e-0006-4c3a-9d10-000000000006',
  '5b0c6a1e-0007-4c3a-9d10-000000000007',
  '5b0c6a1e-0008-4c3a-9d10-000000000008',
  '5b0c6a1e-0009-4c3a-9d10-000000000009',
  '5b0c6a1e-0010-4c3a-9d10-000000000010',
];

const STICKY_NOTE = `## HubSpot Post-Call MEDDIC/BANT Extractor

Generated from src/ by scripts/build-n8n-workflow.js. Do not edit the Code nodes by hand: change src/ and run \`npm run build:workflow\`.

**Safe by default:** DRY_RUN and SANDBOX_MODE are treated as true unless the environment sets them to false.

**n8n environment requirements**
- \`NODE_FUNCTION_ALLOW_BUILTIN=crypto\` (HMAC verification)
- \`N8N_BLOCK_ENV_ACCESS_IN_NODE=false\` (all settings come from $env)
- Set the same variables as .env.example on the n8n host.

**Privacy:** successful executions are not saved (workflow setting) because items carry call content.`;

export function buildWorkflow(root = ROOT) {
  const library = buildLibrarySource(root);
  const rules = JSON.parse(fs.readFileSync(path.join(root, 'config', 'qualification-rules.example.json'), 'utf8'));
  const header = [
    '// AUTO-GENERATED by scripts/build-n8n-workflow.js from src/. Edit src/, then run `npm run build:workflow`.',
    "const crypto = require('crypto');",
    `const EMBEDDED_QUALIFICATION_RULES = ${JSON.stringify(rules)};`,
  ].join('\n');

  const nodes = [
    {
      parameters: { content: STICKY_NOTE, height: 420, width: 520 },
      id: NODE_IDS[9],
      name: 'Read Me',
      type: 'n8n-nodes-base.stickyNote',
      typeVersion: 1,
      position: [-40, -460],
    },
    {
      parameters: {
        httpMethod: 'POST',
        path: 'post-call-meddic-bant',
        responseMode: 'responseNode',
        options: { rawBody: true },
      },
      id: NODE_IDS[0],
      name: 'Post-Call Webhook',
      type: 'n8n-nodes-base.webhook',
      typeVersion: 2,
      position: [0, 0],
      webhookId: '7d1e2f30-0000-4a5b-8c6d-000000000b01',
    },
  ];
  STAGES.forEach((stage, i) => {
    nodes.push({
      parameters: { jsCode: `${header}\n\n${library}\n\n// ---- n8n stage runner ----${PRELUDE}\n${stage.body}\n` },
      id: NODE_IDS[i + 1],
      name: stage.name,
      type: 'n8n-nodes-base.code',
      typeVersion: 2,
      position: [240 * (i + 1), 0],
    });
  });
  nodes.push({
    parameters: {
      respondWith: 'json',
      responseBody: '={{ JSON.stringify($json.response) }}',
      options: { responseCode: '={{ $json.httpStatus }}' },
    },
    id: NODE_IDS[8],
    name: 'Respond to Webhook',
    type: 'n8n-nodes-base.respondToWebhook',
    typeVersion: 1.1,
    position: [240 * (STAGES.length + 1), 0],
  });

  const chain = ['Post-Call Webhook', ...STAGES.map((s) => s.name), 'Respond to Webhook'];
  const connections = {};
  for (let i = 0; i < chain.length - 1; i += 1) {
    connections[chain[i]] = { main: [[{ node: chain[i + 1], type: 'main', index: 0 }]] };
  }

  return {
    name: 'HubSpot Post-Call MEDDIC/BANT Extractor',
    nodes,
    connections,
    active: false,
    settings: {
      executionOrder: 'v1',
      saveDataSuccessExecution: 'none',
      saveDataErrorExecution: 'all',
      saveManualExecutions: false,
    },
    pinData: {},
    meta: { templateCredsSetupCompleted: true },
    tags: [],
  };
}

export function serializeWorkflow(workflow) {
  return `${JSON.stringify(workflow, null, 2)}\n`;
}

const invokedDirectly = process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (invokedDirectly) {
  const json = serializeWorkflow(buildWorkflow());
  fs.writeFileSync(OUTPUT_PATH, json);
  process.stdout.write(`Wrote ${path.relative(ROOT, OUTPUT_PATH)} (${(json.length / 1024).toFixed(1)} KiB)\n`);
}
