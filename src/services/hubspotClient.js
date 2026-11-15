/**
 * HubSpot CRM API v3 client.
 *
 * - Deal lookup: deal ID hint -> external participant email -> company domain.
 * - Deal property upsert (PATCH) and Note creation associated to the deal.
 * - Every mutation passes a safety interlock first:
 *     DRY_RUN=true      -> the request is recorded and returned, never sent.
 *     SANDBOX_MODE=true -> the token's portal must be a sandbox / developer test
 *                          account, or match HUBSPOT_SANDBOX_PORTAL_ID.
 * - A placeholder token switches the client to offline mode (synthetic deal, no network).
 */
import { escapeHtml, isPlaceholder, SafetyInterlockError } from '../utils/security.js';
import { QUALIFICATION_FIELDS, QUALIFICATION_FIELD_KEYS } from '../extractors/meddicBantExtractor.js';

export const NOTE_TO_DEAL_ASSOCIATION_TYPE_ID = 214;
export const DEAL_BASE_PROPERTIES = [
  'dealname',
  'dealstage',
  'pipeline',
  'hubspot_owner_id',
  'hs_is_closed',
  'hs_lastmodifieddate',
  'amount',
  'closedate',
];
export const SANDBOX_ACCOUNT_TYPES = ['SANDBOX', 'DEVELOPER_TEST'];

export class HubSpotApiError extends Error {
  constructor(message, status) {
    super(message);
    this.name = 'HubSpotApiError';
    this.status = status;
    this.code = `http_${status}`;
  }
}

export function listDealPropertiesToRead(rules) {
  const mapped = [];
  for (const key of QUALIFICATION_FIELD_KEYS) {
    const entry = rules?.hubspotPropertyMap?.fields?.[key];
    if (entry) mapped.push(entry.value, entry.confidence);
  }
  return [...new Set([...DEAL_BASE_PROPERTIES, ...mapped])];
}

export function buildHubSpotDealUrl(appBaseUrl, portalId, dealId) {
  if (isPlaceholder(portalId) || !/^\d+$/.test(String(portalId)) || !/^\d+$/.test(String(dealId))) return null;
  return `${(appBaseUrl || 'https://app.hubspot.com').replace(/\/+$/, '')}/contacts/${portalId}/record/0-3/${dealId}`;
}

/** Picks the most recently modified open deal. Closed deals are never auto-selected from email/domain matches. */
export function chooseBestDeal(deals) {
  const open = (deals || []).filter((d) => String(d?.properties?.hs_is_closed) !== 'true');
  open.sort((a, b) => Date.parse(b.properties?.hs_lastmodifieddate || 0) - Date.parse(a.properties?.hs_lastmodifieddate || 0));
  return { deal: open[0] || null, candidates: open.length };
}

/**
 * Decides which deal properties to write. A field is skipped when it is missing,
 * under propertyWrite.minConfidenceToWrite, ungrounded (when required) or would
 * overwrite an existing value that carries a higher stored confidence.
 */
export function buildDealPropertyUpdates({ extraction, gate, existingProperties = {}, rules, normalized, nowIso }) {
  const policy = {
    minConfidenceToWrite: 0.5,
    requireGroundedEvidence: true,
    allowOverwriteWithLowerConfidence: false,
    maxValueLength: 2000,
    ...(rules.propertyWrite || {}),
  };
  const map = rules.hubspotPropertyMap;
  const properties = {};
  const written = [];
  const skipped = [];
  for (const field of QUALIFICATION_FIELDS) {
    const entry = map.fields[field.key];
    const fx = extraction.fields[field.key];
    if (!fx || fx.status === 'missing' || !fx.value) {
      skipped.push({ field: field.key, reason: 'missing' });
      continue;
    }
    if (fx.confidence < policy.minConfidenceToWrite) {
      skipped.push({ field: field.key, reason: 'below_write_threshold' });
      continue;
    }
    if (policy.requireGroundedEvidence && !fx.grounded) {
      skipped.push({ field: field.key, reason: 'ungrounded' });
      continue;
    }
    const existingValue = existingProperties[entry.value];
    const existingConfidence = Number.parseFloat(existingProperties[entry.confidence]);
    if (
      !policy.allowOverwriteWithLowerConfidence &&
      existingValue &&
      String(existingValue).trim() &&
      Number.isFinite(existingConfidence) &&
      fx.confidence < existingConfidence
    ) {
      skipped.push({ field: field.key, reason: 'lower_than_existing_confidence' });
      continue;
    }
    properties[entry.value] = String(fx.value).slice(0, policy.maxValueLength);
    properties[entry.confidence] = fx.confidence.toFixed(2);
    written.push(field.key);
  }
  const summary = map.summary || {};
  const gateStatus = gate?.evaluated ? (gate.passed ? 'passed' : 'blocked') : 'not_evaluated';
  const missingText = (gate?.target?.issues || [])
    .map((issue) => `${issue.label} (${issue.reason.replace(/_/g, ' ')})`)
    .join('; ');
  if (summary.score) properties[summary.score] = String(gate?.score ?? 0);
  if (summary.gateStatus) properties[summary.gateStatus] = gateStatus;
  if (summary.missingFields) properties[summary.missingFields] = missingText;
  if (summary.lastExtractedAt) properties[summary.lastExtractedAt] = nowIso;
  if (summary.sourceCallId) properties[summary.sourceCallId] = `${normalized.source}:${normalized.callId}`.slice(0, 250);
  return { properties, written, skipped };
}

export function buildQualificationNoteHtml({ normalized, extraction, gate, extractionMeta, dryRun }) {
  const statusLabel = gate?.evaluated ? (gate.passed ? 'PASSED' : 'BLOCKED') : 'NOT EVALUATED';
  const rows = QUALIFICATION_FIELDS.map((field) => {
    const fx = extraction.fields[field.key];
    const quote = fx.evidence[0] ? `<br/><em>"${escapeHtml(fx.evidence[0])}"</em>` : '';
    return `<tr><td><strong>${escapeHtml(field.label)}</strong> (${field.frameworks.join('/')})</td><td>${escapeHtml(
      fx.status,
    )}</td><td>${fx.confidence.toFixed(2)}</td><td>${escapeHtml(fx.value || '—')}${quote}</td></tr>`;
  }).join('');
  const issues = (gate?.target?.issues || [])
    .map((i) => `<li>${escapeHtml(i.label)}: ${escapeHtml(i.reason.replace(/_/g, ' '))}</li>`)
    .join('');
  const list = (items) => (items.length ? `<ul>${items.map((s) => `<li>${escapeHtml(s)}</li>`).join('')}</ul>` : '<p>None captured.</p>');
  return [
    `<h3>Post-call MEDDIC/BANT qualification${dryRun ? ' [DRY RUN]' : ''}</h3>`,
    `<p><strong>Call:</strong> ${escapeHtml(normalized.title)} (${escapeHtml(normalized.source)}, ${escapeHtml(
      normalized.startedAt || 'date unknown',
    )})</p>`,
    `<p><strong>Qualification score:</strong> ${gate?.score ?? 0}/100 &nbsp; <strong>Stage gate:</strong> ${statusLabel}${
      gate?.target ? ` for ${escapeHtml(gate.target.label)}` : ''
    }</p>`,
    issues ? `<p><strong>Missing or weak criteria:</strong></p><ul>${issues}</ul>` : '',
    `<p><strong>Summary:</strong> ${escapeHtml(extraction.summary)}</p>`,
    `<table><thead><tr><th>Field</th><th>Status</th><th>Confidence</th><th>Value / evidence</th></tr></thead><tbody>${rows}</tbody></table>`,
    `<p><strong>Next steps</strong></p>${list(extraction.next_steps)}`,
    `<p><strong>Risks</strong></p>${list(extraction.risks)}`,
    `<p><small>Extracted by ${escapeHtml(extractionMeta?.provider || 'unknown')} (${escapeHtml(
      extractionMeta?.model || 'n/a',
    )}). Evidence quotes are verified against the transcript before writing.</small></p>`,
  ]
    .filter(Boolean)
    .join('\n');
}

export function createHubSpotClient({
  token,
  dryRun = true,
  sandboxMode = true,
  sandboxPortalId = '',
  allowedSandboxAccountTypes = SANDBOX_ACCOUNT_TYPES,
  baseUrl = 'https://api.hubapi.com',
  fetchImpl = globalThis.fetch,
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  maxRetries = 3,
}) {
  const offline = isPlaceholder(token);
  const audit = [];
  const apiBase = String(baseUrl).replace(/\/+$/, '');
  let sandboxCheck = null;

  async function send(method, path, body, { allow404 = false } = {}) {
    if (offline) {
      throw new SafetyInterlockError('hubspot_offline', 'HubSpot token is a placeholder; live API calls are disabled');
    }
    for (let attempt = 0; ; attempt += 1) {
      const response = await fetchImpl(`${apiBase}${path}`, {
        method,
        headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
      if (response.status === 404 && allow404) return null;
      if ((response.status === 429 || response.status >= 500) && attempt < maxRetries) {
        const retryAfter = Number(response.headers?.get?.('retry-after'));
        const waitMs = Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter * 1000 : 500 * 2 ** attempt;
        await sleep(Math.min(waitMs, 10000));
        continue;
      }
      if (!response.ok) {
        throw new HubSpotApiError(`HubSpot ${method} ${path.split('?')[0]} failed with HTTP ${response.status}`, response.status);
      }
      const text = await response.text();
      return text ? JSON.parse(text) : {};
    }
  }

  async function verifySandboxAccount() {
    if (!sandboxCheck) {
      sandboxCheck = (async () => {
        const details = await send('GET', '/account-info/v3/details');
        const portalId = String(details?.portalId ?? '');
        const accountType = String(details?.accountType ?? '').toUpperCase();
        if (!isPlaceholder(sandboxPortalId)) {
          if (portalId !== String(sandboxPortalId)) {
            throw new SafetyInterlockError(
              'sandbox_portal_mismatch',
              'SANDBOX_MODE=true but the token belongs to a portal other than HUBSPOT_SANDBOX_PORTAL_ID',
            );
          }
          return { portalId, accountType };
        }
        if (!allowedSandboxAccountTypes.includes(accountType)) {
          throw new SafetyInterlockError(
            'sandbox_account_required',
            `SANDBOX_MODE=true but the token's account type is "${accountType || 'unknown'}", not a sandbox or developer test account`,
          );
        }
        return { portalId, accountType };
      })();
    }
    return sandboxCheck;
  }

  async function mutate(method, path, body) {
    if (dryRun) {
      const record = { intercepted: true, reason: 'dry_run', method, path, body };
      audit.push(record);
      return record;
    }
    if (sandboxMode) await verifySandboxAccount();
    const result = await send(method, path, body);
    audit.push({ intercepted: false, reason: sandboxMode ? 'sandbox_live' : 'live', method, path });
    return { intercepted: false, result };
  }

  async function getDeal(dealId, properties) {
    const query = properties?.length ? `?properties=${encodeURIComponent(properties.join(','))}` : '';
    return send('GET', `/crm/v3/objects/deals/${encodeURIComponent(dealId)}${query}`, undefined, { allow404: true });
  }

  async function searchObjects(objectType, propertyName, values) {
    if (!values.length) return [];
    const body = {
      filterGroups: [{ filters: [{ propertyName, operator: 'IN', values: values.slice(0, 100) }] }],
      properties: [propertyName],
      limit: 10,
    };
    const result = await send('POST', `/crm/v3/objects/${objectType}/search`, body);
    return result?.results || [];
  }

  async function associatedDealIds(fromObjectType, objectId) {
    const result = await send(
      'GET',
      `/crm/v4/objects/${fromObjectType}/${encodeURIComponent(objectId)}/associations/deals?limit=100`,
    );
    return (result?.results || []).map((r) => String(r.toObjectId));
  }

  async function batchReadDeals(ids, properties) {
    if (!ids.length) return [];
    const result = await send('POST', '/crm/v3/objects/deals/batch/read', {
      properties,
      inputs: ids.slice(0, 100).map((id) => ({ id })),
    });
    return result?.results || [];
  }

  async function dealsFromObjects(objectType, objects, properties) {
    const ids = new Set();
    for (const obj of objects.slice(0, 5)) {
      for (const id of await associatedDealIds(objectType, obj.id)) ids.add(id);
    }
    return batchReadDeals([...ids], properties);
  }

  async function findDeal(normalized, { properties = DEAL_BASE_PROPERTIES, offlineStageId = 'qualifiedtobuy' } = {}) {
    if (offline) {
      return {
        deal: {
          id: normalized.crm?.dealIdHint || 'offline-simulated-deal',
          properties: {
            dealname: `${normalized.title} (offline simulation)`,
            dealstage: offlineStageId,
            pipeline: 'default',
            hs_is_closed: 'false',
          },
        },
        matchedBy: 'offline_simulation',
        candidates: 1,
        ambiguous: false,
      };
    }
    const hint = normalized.crm?.dealIdHint;
    if (hint) {
      const deal = await getDeal(hint, properties);
      if (deal) return { deal, matchedBy: 'deal_id', candidates: 1, ambiguous: false };
    }
    const contacts = await searchObjects('contacts', 'email', normalized.externalEmails || []);
    if (contacts.length) {
      const { deal, candidates } = chooseBestDeal(await dealsFromObjects('contacts', contacts, properties));
      if (deal) return { deal, matchedBy: 'participant_email', candidates, ambiguous: candidates > 1 };
    }
    const companies = await searchObjects('companies', 'domain', normalized.externalDomains || []);
    if (companies.length) {
      const { deal, candidates } = chooseBestDeal(await dealsFromObjects('companies', companies, properties));
      if (deal) return { deal, matchedBy: 'company_domain', candidates, ambiguous: candidates > 1 };
    }
    return { deal: null, matchedBy: null, candidates: 0, ambiguous: false };
  }

  async function updateDeal(dealId, properties) {
    if (!properties || !Object.keys(properties).length) return { intercepted: false, skipped: true };
    return mutate('PATCH', `/crm/v3/objects/deals/${encodeURIComponent(dealId)}`, { properties });
  }

  async function createDealNote(dealId, bodyHtml, timestampIso) {
    return mutate('POST', '/crm/v3/objects/notes', {
      properties: { hs_timestamp: timestampIso, hs_note_body: bodyHtml },
      associations: [
        {
          to: { id: String(dealId) },
          types: [{ associationCategory: 'HUBSPOT_DEFINED', associationTypeId: NOTE_TO_DEAL_ASSOCIATION_TYPE_ID }],
        },
      ],
    });
  }

  return {
    offline,
    dryRun,
    sandboxMode,
    findDeal,
    getDeal,
    updateDeal,
    createDealNote,
    verifySandboxAccount,
    auditLog: () => audit.slice(),
  };
}
