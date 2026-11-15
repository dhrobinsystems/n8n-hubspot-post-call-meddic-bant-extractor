/**
 * Pipeline stages shared by the Node.js server (src/index.js) and the n8n workflow.
 *
 * Each stage takes a JSON-serializable context object and returns a new one, so the
 * same functions run inside n8n Code nodes (one stage per node) and in the Node.js
 * mirror (all stages chained by processWebhook). Stages skip themselves once the
 * context status is no longer "accepted", so a failure flows straight to the response.
 */
import {
  isPlaceholder,
  sanitizeString,
  sanitizeTranscript,
  verifyWebhookSignature,
  SafetyInterlockError,
} from './utils/security.js';
import { normalizeTranscriptPayload, NormalizationError } from './normalizers/transcriptNormalizer.js';
import { extractQualification } from './extractors/meddicBantExtractor.js';
import { evaluateStageGate } from './validators/stageGateValidator.js';
import {
  buildDealPropertyUpdates,
  buildHubSpotDealUrl,
  buildQualificationNoteHtml,
  createHubSpotClient,
  listDealPropertiesToRead,
  HubSpotApiError,
} from './services/hubspotClient.js';
import {
  buildDealBriefMessage,
  buildGateAlertMessage,
  buildUnmatchedDealMessage,
  createSlackNotifier,
} from './services/slackNotifier.js';

export const SUPPORTED_LLM_PROVIDERS = ['mock', 'openai', 'anthropic'];

/** true/1/yes/on -> true, false/0/no/off -> false, anything else -> the default (fail-safe). */
export function parseBoolFlag(value, defaultValue) {
  if (value === undefined || value === null) return defaultValue;
  const v = String(value).trim().toLowerCase();
  if (['true', '1', 'yes', 'on'].includes(v)) return true;
  if (['false', '0', 'no', 'off'].includes(v)) return false;
  return defaultValue;
}

function parseIntOr(value, fallback) {
  const n = Number.parseInt(String(value ?? ''), 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

function parseJsonObjectOr(value, fallback) {
  if (!value) return fallback;
  try {
    const parsed = JSON.parse(value);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : fallback;
  } catch {
    return fallback;
  }
}

export function loadConfig(env = {}) {
  const read = (key, fallback = '') => {
    const value = env[key];
    return value === undefined || value === null ? fallback : String(value).trim();
  };
  const provider = read('LLM_PROVIDER', 'mock').toLowerCase() || 'mock';
  return {
    dryRun: parseBoolFlag(env.DRY_RUN, true),
    sandboxMode: parseBoolFlag(env.SANDBOX_MODE, true),
    redactPii: parseBoolFlag(env.PII_REDACTION, true),
    internalDomains: read('INTERNAL_EMAIL_DOMAINS', 'example.com')
      .split(',')
      .map((d) => d.trim().toLowerCase())
      .filter(Boolean),
    webhook: {
      secret: read('WEBHOOK_SIGNING_SECRET'),
      signatureHeader: read('WEBHOOK_SIGNATURE_HEADER', 'x-signature').toLowerCase(),
      timestampHeader: read('WEBHOOK_TIMESTAMP_HEADER', 'x-signature-timestamp').toLowerCase(),
      requireSignature: parseBoolFlag(env.WEBHOOK_REQUIRE_SIGNATURE, true),
      requireTimestamp: parseBoolFlag(env.WEBHOOK_REQUIRE_TIMESTAMP, false),
      toleranceSeconds: parseIntOr(env.WEBHOOK_TOLERANCE_SECONDS, 300),
      maxBodyBytes: parseIntOr(env.WEBHOOK_MAX_BODY_BYTES, 2000000),
    },
    llm: {
      provider,
      model: read('LLM_MODEL'),
      apiKey: provider === 'anthropic' ? read('ANTHROPIC_API_KEY') : provider === 'openai' ? read('OPENAI_API_KEY') : '',
      baseUrl: provider === 'anthropic' ? read('ANTHROPIC_BASE_URL') : read('OPENAI_BASE_URL'),
      timeoutMs: parseIntOr(env.LLM_TIMEOUT_MS, 60000),
      maxAttempts: parseIntOr(env.LLM_MAX_ATTEMPTS, 2),
      maxTranscriptChars: parseIntOr(env.MAX_TRANSCRIPT_CHARS, 60000),
    },
    hubspot: {
      token: read('HUBSPOT_PRIVATE_APP_TOKEN'),
      portalId: read('HUBSPOT_PORTAL_ID'),
      sandboxPortalId: read('HUBSPOT_SANDBOX_PORTAL_ID'),
      baseUrl: read('HUBSPOT_BASE_URL', 'https://api.hubapi.com'),
      appBaseUrl: read('HUBSPOT_APP_BASE_URL', 'https://app.hubspot.com'),
      offlineStageId: read('SIMULATE_DEAL_STAGE_ID', 'qualifiedtobuy'),
    },
    slack: {
      webhookUrl: read('SLACK_WEBHOOK_URL'),
      botToken: read('SLACK_BOT_TOKEN'),
      channelId: read('SLACK_CHANNEL_ID'),
      sandboxWebhookUrl: read('SLACK_SANDBOX_WEBHOOK_URL'),
      sandboxChannelId: read('SLACK_SANDBOX_CHANNEL_ID'),
      ownerSlackMap: parseJsonObjectOr(read('OWNER_SLACK_MAP_JSON'), {}),
    },
  };
}

/** Errors block processing; warnings are reported. Live mode (DRY_RUN=false) is strict. */
export function validateConfigForMode(config) {
  const errors = [];
  const warnings = [];
  const live = !config.dryRun;
  if (!SUPPORTED_LLM_PROVIDERS.includes(config.llm.provider)) {
    errors.push(`LLM_PROVIDER must be one of ${SUPPORTED_LLM_PROVIDERS.join(', ')}`);
  } else if (config.llm.provider !== 'mock') {
    if (!config.llm.model) errors.push('LLM_MODEL is required when LLM_PROVIDER is openai or anthropic');
    if (isPlaceholder(config.llm.apiKey)) errors.push(`${config.llm.provider.toUpperCase()}_API_KEY is missing or a placeholder`);
  }
  if (!config.webhook.requireSignature) {
    if (live) errors.push('WEBHOOK_REQUIRE_SIGNATURE=false is only allowed with DRY_RUN=true');
    else warnings.push('Webhook signature verification is disabled (dry run only)');
  } else if (isPlaceholder(config.webhook.secret)) {
    if (live) errors.push('WEBHOOK_SIGNING_SECRET is missing or a placeholder');
    else warnings.push('WEBHOOK_SIGNING_SECRET is a placeholder (acceptable for dry-run simulation only)');
  }
  if (live) {
    if (config.llm.provider === 'mock') errors.push('LLM_PROVIDER=mock cannot write to HubSpot; set DRY_RUN=true or choose a real provider');
    if (isPlaceholder(config.hubspot.token)) errors.push('HUBSPOT_PRIVATE_APP_TOKEN is missing or a placeholder');
  }
  if (!config.sandboxMode && live) warnings.push('SANDBOX_MODE=false and DRY_RUN=false: production HubSpot and Slack will be modified');
  return { errors, warnings };
}

/** Idempotency store over a plain object (works with n8n workflow static data and in memory). */
export function createSeenStore(backing = {}, { ttlMs = 7 * 24 * 3600 * 1000, maxEntries = 5000 } = {}) {
  function prune(now) {
    const keys = Object.keys(backing);
    for (const key of keys) if (now - backing[key] > ttlMs) delete backing[key];
    const remaining = Object.keys(backing);
    if (remaining.length > maxEntries) {
      remaining
        .sort((a, b) => backing[a] - backing[b])
        .slice(0, remaining.length - maxEntries)
        .forEach((key) => delete backing[key]);
    }
  }
  return {
    has(key, now = Date.now()) {
      prune(now);
      return Object.prototype.hasOwnProperty.call(backing, key);
    },
    add(key, now = Date.now()) {
      backing[key] = now;
      prune(now);
    },
    size: () => Object.keys(backing).length,
  };
}

export function getHeader(headers, name) {
  if (!headers || !name) return null;
  const wanted = String(name).toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === wanted) return Array.isArray(value) ? value[0] : value;
  }
  return null;
}

function failContext(ctx, httpStatus, reason, error) {
  return { ...ctx, status: 'failed', httpStatus, reason, error: error ? sanitizeString(error, 300) : null };
}

function rejectContext(base, httpStatus, reason, status = 'rejected') {
  return { ...base, status, httpStatus, reason };
}

function mergeCounts(a = {}, b = {}) {
  const out = { ...a };
  for (const [k, v] of Object.entries(b)) out[k] = (out[k] || 0) + v;
  return out;
}

export function createClientsFromConfig(config, { fetchImpl, sleep } = {}) {
  const hubspot = createHubSpotClient({
    token: config.hubspot.token,
    dryRun: config.dryRun,
    sandboxMode: config.sandboxMode,
    sandboxPortalId: config.hubspot.sandboxPortalId,
    baseUrl: config.hubspot.baseUrl,
    fetchImpl,
    ...(sleep ? { sleep } : {}),
  });
  const slack = createSlackNotifier({ ...config.slack, dryRun: config.dryRun, sandboxMode: config.sandboxMode, fetchImpl });
  return { hubspot, slack };
}

export async function ingestStage(input, { config, seenStore, now = Date.now() }) {
  const base = {
    status: 'accepted',
    httpStatus: 200,
    reason: null,
    receivedAt: new Date(now).toISOString(),
    dryRun: config.dryRun,
    sandboxMode: config.sandboxMode,
    warnings: [],
  };
  const configCheck = validateConfigForMode(config);
  if (configCheck.errors.length) {
    return { ...rejectContext(base, 500, 'config_invalid', 'failed'), error: configCheck.errors.join('; ') };
  }
  base.warnings = configCheck.warnings;
  try {
    const rawBody = typeof input.rawBody === 'string' ? input.rawBody : '';
    if (Buffer.byteLength(rawBody, 'utf8') > config.webhook.maxBodyBytes) return rejectContext(base, 413, 'payload_too_large');
    if (config.webhook.requireSignature) {
      const verdict = verifyWebhookSignature({
        rawBody,
        signatureHeader: getHeader(input.headers, config.webhook.signatureHeader),
        timestampHeader: getHeader(input.headers, config.webhook.timestampHeader),
        secret: config.webhook.secret,
        toleranceSeconds: config.webhook.toleranceSeconds,
        requireTimestamp: config.webhook.requireTimestamp,
        now,
      });
      if (!verdict.valid) return rejectContext(base, 401, `webhook_${verdict.reason}`);
    }
    let payload;
    try {
      payload = JSON.parse(rawBody);
    } catch {
      return rejectContext(base, 400, 'invalid_json');
    }
    const sourceHint = getHeader(input.headers, 'x-transcript-source') || input.query?.source || null;
    const normalized = normalizeTranscriptPayload(payload, { sourceHint, internalDomains: config.internalDomains });
    const idempotencyKey = `${normalized.source}:${normalized.callId}`;
    if (seenStore && seenStore.has(idempotencyKey, now)) {
      return { ...rejectContext(base, 200, 'already_processed', 'duplicate'), idempotencyKey, call: { source: normalized.source, callId: normalized.callId } };
    }
    const transcript = sanitizeTranscript(normalized.transcript, { maxChars: config.llm.maxTranscriptChars, redact: config.redactPii });
    const summary = normalized.summary ? sanitizeTranscript(normalized.summary, { maxChars: 8000, redact: config.redactPii }) : null;
    const { transcript: _rawTranscript, summary: _rawSummary, ...call } = normalized;
    return {
      ...base,
      idempotencyKey,
      call,
      content: { transcript: transcript.text, summary: summary ? summary.text : null },
      privacy: {
        piiRedaction: config.redactPii,
        redactions: mergeCounts(transcript.redactions, summary ? summary.redactions : {}),
        truncated: transcript.truncated,
        originalTranscriptChars: transcript.originalLength,
        sentTranscriptChars: transcript.finalLength,
      },
    };
  } catch (err) {
    if (err instanceof NormalizationError) return rejectContext(base, 422, `normalization_${err.code}`);
    return { ...rejectContext(base, 500, 'ingest_error', 'failed'), error: sanitizeString(err && err.message, 300) };
  }
}

export async function extractStage(ctx, { config, fetchImpl }) {
  if (ctx.status !== 'accepted') return ctx;
  const { content, ...rest } = ctx;
  try {
    const result = await extractQualification({
      normalized: ctx.call,
      transcriptText: content.transcript,
      summaryText: content.summary,
      llm: config.llm,
      fetchImpl,
    });
    return {
      ...rest,
      extraction: result.data,
      extractionMeta: { provider: result.provider, model: result.model, attempts: result.attempts, warnings: result.warnings },
    };
  } catch (err) {
    return failContext(rest, 502, `extraction_${err.code || 'error'}`, err && err.message);
  }
}

export async function resolveDealStage(ctx, { config, rules, hubspot }) {
  if (ctx.status !== 'accepted') return ctx;
  try {
    const properties = listDealPropertiesToRead(rules);
    const match = await hubspot.findDeal(ctx.call, { properties, offlineStageId: config.hubspot.offlineStageId });
    const { externalEmails: _emails, ...call } = ctx.call;
    call.participants = (call.participants || []).map((p) => ({ name: p.name, role: p.role }));
    const deal = match.deal
      ? {
          id: String(match.deal.id),
          properties: Object.fromEntries(properties.map((p) => [p, match.deal.properties?.[p] ?? null])),
          url: buildHubSpotDealUrl(config.hubspot.appBaseUrl, config.hubspot.portalId, match.deal.id),
        }
      : null;
    return {
      ...ctx,
      call,
      deal,
      dealMatch: { matchedBy: match.matchedBy, candidates: match.candidates, ambiguous: match.ambiguous, offline: hubspot.offline },
    };
  } catch (err) {
    const status = err instanceof HubSpotApiError ? 502 : err instanceof SafetyInterlockError ? 503 : 500;
    return failContext(ctx, status, `deal_lookup_${err.code || 'error'}`, err && err.message);
  }
}

export async function gateStage(ctx, { rules, targetStageId = null }) {
  if (ctx.status !== 'accepted') return ctx;
  if (!ctx.deal) {
    return { ...ctx, gate: { evaluated: false, reason: 'no_deal_match', passed: false, blockAdvance: false, score: null, alert: { slack: false } } };
  }
  const gate = evaluateStageGate({
    extraction: ctx.extraction,
    rules,
    pipelineId: ctx.deal.properties.pipeline,
    currentStageId: ctx.deal.properties.dealstage,
    targetStageId,
  });
  return { ...ctx, gate };
}

function describeMutation(result) {
  if (!result) return 'skipped';
  if (result.skipped) return 'skipped';
  return result.intercepted ? 'intercepted_dry_run' : 'written';
}

export async function writeStage(ctx, { config, rules, hubspot, now = Date.now() }) {
  if (ctx.status !== 'accepted') return ctx;
  if (!ctx.deal) return { ...ctx, hubspotActions: { skipped: 'no_deal_match' } };
  const nowIso = new Date(now).toISOString();
  try {
    const updates = buildDealPropertyUpdates({
      extraction: ctx.extraction,
      gate: ctx.gate,
      existingProperties: ctx.deal.properties,
      rules,
      normalized: ctx.call,
      nowIso,
    });
    const writeEnabled = rules.propertyWrite?.enabled !== false;
    const propertyResult = writeEnabled ? await hubspot.updateDeal(ctx.deal.id, updates.properties) : { skipped: true };
    const noteEnabled = rules.note?.enabled !== false;
    const noteHtml = buildQualificationNoteHtml({
      normalized: ctx.call,
      extraction: ctx.extraction,
      gate: ctx.gate,
      extractionMeta: ctx.extractionMeta,
      dryRun: config.dryRun,
    });
    const noteResult = noteEnabled ? await hubspot.createDealNote(ctx.deal.id, noteHtml, nowIso) : { skipped: true };
    return {
      ...ctx,
      hubspotActions: {
        propertyUpdate: {
          mode: writeEnabled ? describeMutation(propertyResult) : 'disabled',
          written: updates.written,
          skipped: updates.skipped,
          properties: config.dryRun ? updates.properties : undefined,
        },
        note: {
          mode: noteEnabled ? describeMutation(noteResult) : 'disabled',
          noteId: noteResult?.result?.id || null,
          bodyLength: noteHtml.length,
        },
      },
    };
  } catch (err) {
    const status = err instanceof SafetyInterlockError ? 503 : err instanceof HubSpotApiError ? 502 : 500;
    return failContext(ctx, status, `hubspot_write_${err.code || 'error'}`, err && err.message);
  }
}

export function chooseSlackMessage(ctx, { rules, config }) {
  const notifications = rules.notifications || {};
  const flags = { dryRun: config.dryRun, sandboxMode: config.sandboxMode };
  if (!ctx.deal) return notifications.alertOnUnmatchedDeal !== false ? buildUnmatchedDealMessage({ normalized: ctx.call, flags }) : null;
  const ownerId = ctx.deal.properties.hubspot_owner_id;
  const common = { normalized: ctx.call, deal: ctx.deal, dealUrl: ctx.deal.url, gate: ctx.gate, dealMatch: ctx.dealMatch, flags };
  if (ctx.gate.alert?.slack) {
    const ownerSlackId = ctx.gate.alert.mentionOwner && ownerId ? config.slack.ownerSlackMap[ownerId] || null : null;
    return buildGateAlertMessage({ ...common, ownerSlackId });
  }
  if (ctx.gate.evaluated && ctx.gate.passed && notifications.sendDealBriefOnPass !== false) {
    return buildDealBriefMessage({ ...common, extraction: ctx.extraction });
  }
  if (ctx.dealMatch?.ambiguous && notifications.alertOnAmbiguousDeal !== false) {
    return buildDealBriefMessage({ ...common, extraction: ctx.extraction });
  }
  return null;
}

export async function notifyStage(ctx, { config, rules, slack }) {
  if (ctx.status !== 'accepted') return ctx;
  const message = chooseSlackMessage(ctx, { rules, config });
  if (!message) return { ...ctx, slackAction: { mode: 'skipped', kind: null } };
  try {
    const result = await slack.send(message);
    return { ...ctx, slackAction: { mode: result.mode, kind: result.kind, environment: result.environment || null } };
  } catch (err) {
    return {
      ...ctx,
      warnings: [...(ctx.warnings || []), `Slack notification failed: ${sanitizeString(err && err.message, 200)}`],
      slackAction: { mode: 'error', kind: message.kind, code: err.code || null },
    };
  }
}

export function buildResponseSummary(ctx) {
  const gate = ctx.gate || null;
  return {
    status: ctx.status,
    reason: ctx.reason || null,
    error: ctx.error || null,
    dryRun: ctx.dryRun,
    sandboxMode: ctx.sandboxMode,
    source: ctx.call?.source || null,
    callId: ctx.call?.callId || null,
    deal: ctx.deal ? { id: ctx.deal.id, name: ctx.deal.properties.dealname, stage: ctx.deal.properties.dealstage } : null,
    dealMatch: ctx.dealMatch || null,
    gate: gate
      ? {
          evaluated: gate.evaluated,
          reason: gate.reason || null,
          passed: gate.passed,
          blockAdvance: gate.blockAdvance,
          targetStageId: gate.target?.stageId || null,
          issues: (gate.target?.issues || []).map((i) => ({ field: i.field, reason: i.reason })),
          currentStageIssues: (gate.current?.issues || []).map((i) => ({ field: i.field, reason: i.reason })),
        }
      : null,
    score: gate?.score ?? null,
    fields: ctx.extraction
      ? Object.fromEntries(Object.entries(ctx.extraction.fields).map(([k, f]) => [k, { status: f.status, confidence: f.confidence }]))
      : null,
    extraction: ctx.extractionMeta ? { provider: ctx.extractionMeta.provider, model: ctx.extractionMeta.model, attempts: ctx.extractionMeta.attempts } : null,
    privacy: ctx.privacy || null,
    actions: { hubspot: ctx.hubspotActions || null, slack: ctx.slackAction || null },
    warnings: [...(ctx.warnings || []), ...(ctx.extractionMeta?.warnings || [])],
  };
}

export async function finalizeStage(ctx, { seenStore, now = Date.now() }) {
  let next = ctx;
  if (ctx.status === 'accepted') {
    if (seenStore && ctx.idempotencyKey) seenStore.add(ctx.idempotencyKey, now);
    next = { ...ctx, status: 'processed' };
  }
  return { ...next, response: buildResponseSummary(next) };
}

/** Node.js mirror of the n8n workflow: the same stages, in the same order. */
export async function processWebhook(input, { config, rules, fetchImpl = globalThis.fetch, seenStore, clients, now = () => Date.now() }) {
  const { hubspot, slack } = clients || createClientsFromConfig(config, { fetchImpl });
  let ctx = await ingestStage(input, { config, seenStore, now: now() });
  ctx = await extractStage(ctx, { config, fetchImpl });
  ctx = await resolveDealStage(ctx, { config, rules, hubspot });
  ctx = await gateStage(ctx, { rules });
  ctx = await writeStage(ctx, { config, rules, hubspot, now: now() });
  ctx = await notifyStage(ctx, { config, rules, slack });
  ctx = await finalizeStage(ctx, { seenStore, now: now() });
  return { httpStatus: ctx.httpStatus, body: ctx.response, context: ctx };
}
