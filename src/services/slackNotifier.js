/**
 * Slack Block Kit messages for blocked stage gates, deal briefs and unmatched calls,
 * plus a sender that honours DRY_RUN and routes SANDBOX_MODE traffic to a sandbox target only.
 */
import { isPlaceholder, sanitizeString, SafetyInterlockError } from '../utils/security.js';

const SLACK_WEBHOOK_PREFIX = 'https://hooks.slack.com/';
const SLACK_SECTION_LIMIT = 2900;
const REASON_ICONS = { missing: ':x:', low_confidence: ':large_orange_diamond:', ungrounded: ':mag:' };

export function escapeSlackText(value) {
  return String(value ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function slackSafe(value, max = 300) {
  return escapeSlackText(sanitizeString(value, max));
}

function clampSection(text) {
  return text.length > SLACK_SECTION_LIMIT ? `${text.slice(0, SLACK_SECTION_LIMIT - 1)}…` : text;
}

function describeIssue(issue) {
  const icon = REASON_ICONS[issue.reason] || ':warning:';
  if (issue.reason === 'missing') return `${icon} *${issue.label}*: not captured on this call`;
  if (issue.reason === 'low_confidence') {
    return `${icon} *${issue.label}*: confidence ${issue.confidence.toFixed(2)} is below ${issue.minConfidence.toFixed(2)}`;
  }
  return `${icon} *${issue.label}*: no verbatim transcript evidence`;
}

function modePrefix({ dryRun, sandboxMode }) {
  if (dryRun) return '[DRY RUN] ';
  if (sandboxMode) return '[SANDBOX] ';
  return '';
}

function callContextBlock(normalized, extra = []) {
  const title = slackSafe(normalized.title, 150);
  const link = normalized.url ? `<${normalized.url}|${title}>` : title;
  const parts = [`Call: ${link}`, slackSafe(normalized.source, 20), slackSafe(normalized.startedAt || 'date unknown', 40), ...extra];
  return { type: 'context', elements: [{ type: 'mrkdwn', text: parts.join(' · ') }] };
}

function dealFieldsBlock({ deal, dealUrl, gate }) {
  const dealName = slackSafe(deal?.properties?.dealname || `Deal ${deal?.id}`, 150);
  const dealText = dealUrl ? `<${dealUrl}|${dealName}>` : dealName;
  const stageText = gate?.evaluated
    ? `${slackSafe(gate.current?.label || gate.currentStageId, 80)} → ${slackSafe(gate.target?.label || 'n/a', 80)}`
    : slackSafe(gate?.currentStageId || 'unknown', 80);
  return {
    type: 'section',
    fields: [
      { type: 'mrkdwn', text: `*Deal*\n${dealText}` },
      { type: 'mrkdwn', text: `*Stage → next gate*\n${stageText}` },
      { type: 'mrkdwn', text: `*Qualification score*\n${gate?.score ?? 0}/100` },
      { type: 'mrkdwn', text: `*Pipeline*\n${slackSafe(gate?.pipelineLabel || 'default', 80)}` },
    ],
  };
}

export function buildGateAlertMessage({ normalized, deal, dealUrl, gate, dealMatch, ownerSlackId, flags }) {
  const prefix = modePrefix(flags);
  const dealName = sanitizeString(deal?.properties?.dealname || `Deal ${deal?.id}`, 100);
  const blocks = [
    { type: 'header', text: { type: 'plain_text', text: `${prefix}Qualification gate blocked: ${dealName}`.slice(0, 150) } },
    dealFieldsBlock({ deal, dealUrl, gate }),
  ];
  if (!gate.evaluated) {
    blocks.push({
      type: 'section',
      text: {
        type: 'mrkdwn',
        text: `:grey_question: Stage gate not evaluated (${slackSafe(gate.reason, 60)}). Add this stage to the qualification rules.`,
      },
    });
  }
  if (gate.target && !gate.target.passed) {
    blocks.push({
      type: 'section',
      text: {
        type: 'mrkdwn',
        text: clampSection(
          `*Required before entering ${slackSafe(gate.target.label, 80)}:*\n${gate.target.issues.map(describeIssue).join('\n')}`,
        ),
      },
    });
  }
  if (gate.current && !gate.current.passed) {
    blocks.push({
      type: 'section',
      text: {
        type: 'mrkdwn',
        text: clampSection(
          `*Already in ${slackSafe(gate.current.label, 80)} without:*\n${gate.current.issues.map(describeIssue).join('\n')}`,
        ),
      },
    });
  }
  if (gate.blockAdvance) {
    blocks.push({ type: 'section', text: { type: 'mrkdwn', text: ':no_entry: Hold the stage change until these are captured.' } });
  }
  if (ownerSlackId) {
    blocks.push({ type: 'section', text: { type: 'mrkdwn', text: `Deal owner: <@${escapeSlackText(ownerSlackId)}>` } });
  }
  const extra = dealMatch?.ambiguous ? [`:warning: ${dealMatch.candidates} open deals matched, most recent selected`] : [];
  blocks.push(callContextBlock(normalized, extra));
  const missingLabels = (gate.target?.issues || []).map((i) => i.label).join(', ') || 'see details';
  return { kind: 'gate_alert', text: `${prefix}Qualification gate blocked for ${dealName}: ${missingLabels}`, blocks };
}

export function buildDealBriefMessage({ normalized, deal, dealUrl, gate, extraction, dealMatch, flags }) {
  const prefix = modePrefix(flags);
  const dealName = sanitizeString(deal?.properties?.dealname || `Deal ${deal?.id}`, 100);
  const bullets = (items) => (items.length ? items.map((s) => `• ${slackSafe(s, 280)}`).join('\n') : '_None captured_');
  const captured = Object.entries(extraction.fields)
    .filter(([, f]) => f.status !== 'missing')
    .map(([key]) => key.replace(/_/g, ' '))
    .join(', ');
  const blocks = [
    { type: 'header', text: { type: 'plain_text', text: `${prefix}Deal brief: ${dealName}`.slice(0, 150) } },
    dealFieldsBlock({ deal, dealUrl, gate }),
    { type: 'section', text: { type: 'mrkdwn', text: clampSection(`*Summary*\n${slackSafe(extraction.summary, 1500)}`) } },
    { type: 'section', text: { type: 'mrkdwn', text: clampSection(`*Captured*\n${escapeSlackText(captured || 'nothing')}`) } },
    { type: 'section', text: { type: 'mrkdwn', text: clampSection(`*Next steps*\n${bullets(extraction.next_steps)}`) } },
    { type: 'section', text: { type: 'mrkdwn', text: clampSection(`*Risks*\n${bullets(extraction.risks)}`) } },
  ];
  const extra = dealMatch?.ambiguous ? [`:warning: ${dealMatch.candidates} open deals matched, most recent selected`] : [];
  blocks.push(callContextBlock(normalized, extra));
  return { kind: 'deal_brief', text: `${prefix}Deal brief for ${dealName}: score ${gate?.score ?? 0}/100`, blocks };
}

export function buildUnmatchedDealMessage({ normalized, flags }) {
  const prefix = modePrefix(flags);
  const domains = normalized.externalDomains?.length ? normalized.externalDomains.map((d) => slackSafe(d, 80)).join(', ') : 'none';
  const externalCount = (normalized.participants || []).filter((p) => p.role === 'external').length;
  return {
    kind: 'unmatched_deal',
    text: `${prefix}No HubSpot deal matched call "${sanitizeString(normalized.title, 100)}"`,
    blocks: [
      { type: 'header', text: { type: 'plain_text', text: `${prefix}No HubSpot deal matched`.slice(0, 150) } },
      {
        type: 'section',
        text: {
          type: 'mrkdwn',
          text: `Qualification was extracted but not written. External domains: ${domains}. External participants: ${externalCount}. Associate the contacts or company with an open deal, or pass a deal ID in the payload.`,
        },
      },
      callContextBlock(normalized),
    ],
  };
}

function validWebhookUrl(url) {
  return !isPlaceholder(url) && String(url).startsWith(SLACK_WEBHOOK_PREFIX);
}

export function createSlackNotifier({
  webhookUrl = '',
  botToken = '',
  channelId = '',
  sandboxWebhookUrl = '',
  sandboxChannelId = '',
  dryRun = true,
  sandboxMode = true,
  fetchImpl = globalThis.fetch,
}) {
  function resolveTarget() {
    const hasBot = !isPlaceholder(botToken);
    if (sandboxMode) {
      if (validWebhookUrl(sandboxWebhookUrl)) return { type: 'webhook', url: sandboxWebhookUrl, environment: 'sandbox' };
      if (hasBot && !isPlaceholder(sandboxChannelId)) return { type: 'api', channel: sandboxChannelId, environment: 'sandbox' };
      throw new SafetyInterlockError(
        'slack_sandbox_target_missing',
        'SANDBOX_MODE=true requires SLACK_SANDBOX_WEBHOOK_URL or SLACK_BOT_TOKEN + SLACK_SANDBOX_CHANNEL_ID',
      );
    }
    if (validWebhookUrl(webhookUrl)) return { type: 'webhook', url: webhookUrl, environment: 'production' };
    if (hasBot && !isPlaceholder(channelId)) return { type: 'api', channel: channelId, environment: 'production' };
    return null;
  }

  async function send(message) {
    if (!message) return { mode: 'skipped', kind: null };
    if (dryRun) {
      return { mode: 'intercepted_dry_run', kind: message.kind, environment: sandboxMode ? 'sandbox' : 'production', message };
    }
    const target = resolveTarget();
    if (!target) return { mode: 'not_configured', kind: message.kind };
    const payload = { text: message.text, blocks: message.blocks };
    if (target.type === 'webhook') {
      const response = await fetchImpl(target.url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(payload),
      });
      if (!response.ok) throw new Error(`Slack webhook returned HTTP ${response.status}`);
      return { mode: 'sent', kind: message.kind, environment: target.environment, via: 'webhook' };
    }
    const response = await fetchImpl('https://slack.com/api/chat.postMessage', {
      method: 'POST',
      headers: { 'content-type': 'application/json; charset=utf-8', authorization: `Bearer ${botToken}` },
      body: JSON.stringify({ channel: target.channel, ...payload, unfurl_links: false }),
    });
    const body = JSON.parse((await response.text()) || '{}');
    if (!response.ok || body.ok !== true) throw new Error(`Slack chat.postMessage failed: ${body.error || response.status}`);
    return { mode: 'sent', kind: message.kind, environment: target.environment, via: 'chat.postMessage' };
  }

  return { send, resolveTarget };
}
