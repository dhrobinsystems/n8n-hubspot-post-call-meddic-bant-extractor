/**
 * Normalizes Gong, Fireflies.ai and Fathom post-call payloads into one internal schema:
 *
 * {
 *   schemaVersion: 1,
 *   source: 'gong' | 'fireflies' | 'fathom',
 *   callId, title, startedAt (ISO 8601 | null), durationSeconds (number | null), url (https | null),
 *   participants: [{ name, email | null, role: 'internal' | 'external' | 'unknown' }],
 *   externalDomains: string[], externalEmails: string[],
 *   transcript: 'Speaker Name: text\n...', summary: string | null,
 *   crm: { dealIdHint: string | null }
 * }
 */
import { sanitizeString } from '../utils/security.js';

export const SUPPORTED_SOURCES = ['gong', 'fireflies', 'fathom'];

const FREE_EMAIL_DOMAINS = new Set([
  'gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'live.com', 'yahoo.com',
  'icloud.com', 'me.com', 'aol.com', 'proton.me', 'protonmail.com', 'gmx.com', 'zoho.com',
]);

export function isFreeEmailDomain(domain) {
  return FREE_EMAIL_DOMAINS.has(String(domain || '').toLowerCase());
}

export class NormalizationError extends Error {
  constructor(code, message) {
    super(message || code);
    this.name = 'NormalizationError';
    this.code = code;
  }
}

function toIsoOrNull(value) {
  if (value === undefined || value === null || value === '') return null;
  const date = typeof value === 'number' ? new Date(value < 1e12 ? value * 1000 : value) : new Date(String(value));
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

function toFiniteOrNull(value) {
  const n = Number(value);
  return Number.isFinite(n) && n >= 0 ? n : null;
}

export function normalizeEmail(value) {
  if (!value) return null;
  const email = String(value).trim().toLowerCase();
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ? email : null;
}

export function emailDomain(value) {
  const email = normalizeEmail(value);
  return email ? email.split('@')[1] : null;
}

function safeHttpUrl(value) {
  if (!value) return null;
  const url = String(value).trim();
  return /^https:\/\/[^\s<>"]+$/i.test(url) ? url.slice(0, 2000) : null;
}

function sanitizeDealIdHint(value) {
  if (value === undefined || value === null) return null;
  const id = String(value).trim();
  return /^\d{1,20}$/.test(id) ? id : null;
}

/** Joins consecutive turns by the same speaker into one `Speaker: text` line. */
function mergeSpeakerTurns(turns) {
  const lines = [];
  let current = null;
  for (const turn of turns) {
    const speaker = sanitizeString(turn.speaker, 120) || 'Unknown speaker';
    const text = String(turn.text ?? '').replace(/\s+/g, ' ').trim();
    if (!text) continue;
    if (current && current.speaker === speaker) {
      current.text = `${current.text} ${text}`;
    } else {
      current = { speaker, text };
      lines.push(current);
    }
  }
  return lines.map((line) => `${line.speaker}: ${line.text}`).join('\n');
}

function genericDealIdHint(payload) {
  return sanitizeDealIdHint(
    payload?.hubspot_deal_id ?? payload?.metadata?.hubspot_deal_id ?? payload?.crm?.hubspot_deal_id ?? null,
  );
}

export function detectTranscriptSource(payload, sourceHint) {
  const hint = sourceHint ? String(sourceHint).trim().toLowerCase() : '';
  if (SUPPORTED_SOURCES.includes(hint)) return hint;
  if (payload?.callData?.metaData) return 'gong';
  if (payload?.meetingId && (payload.data || payload.sentences)) return 'fireflies';
  if (payload?.recording_id !== undefined || payload?.calendar_invitees || payload?.default_summary) return 'fathom';
  return null;
}

export function normalizeGongPayload(payload) {
  const call = payload.callData || {};
  const meta = call.metaData || {};
  const parties = Array.isArray(call.parties) ? call.parties : [];
  const bySpeakerId = new Map(parties.filter((p) => p.speakerId !== undefined).map((p) => [String(p.speakerId), p]));
  const participants = parties.map((party) => {
    const affiliation = String(party.affiliation || '').toLowerCase();
    return {
      name: party.name,
      email: party.emailAddress,
      role: affiliation === 'internal' ? 'internal' : affiliation === 'external' ? 'external' : 'unknown',
    };
  });
  const turns = [];
  for (const monologue of Array.isArray(call.transcript) ? call.transcript : []) {
    const speaker = bySpeakerId.get(String(monologue.speakerId))?.name || 'Unknown speaker';
    const text = (Array.isArray(monologue.sentences) ? monologue.sentences : []).map((s) => s.text).join(' ');
    turns.push({ speaker, text });
  }
  let dealIdHint = null;
  for (const ctx of Array.isArray(call.context) ? call.context : []) {
    if (String(ctx.system || '').toLowerCase() !== 'hubspot') continue;
    const deal = (ctx.objects || []).find((o) => String(o.objectType || '').toLowerCase() === 'deal');
    if (deal) dealIdHint = sanitizeDealIdHint(deal.objectId);
  }
  return {
    callId: meta.id,
    title: meta.title,
    startedAt: toIsoOrNull(meta.started),
    durationSeconds: toFiniteOrNull(meta.duration),
    url: safeHttpUrl(meta.url),
    participants,
    transcript: mergeSpeakerTurns(turns),
    summary: call.content?.brief || null,
    dealIdHint: dealIdHint || genericDealIdHint(payload),
  };
}

export function normalizeFirefliesPayload(payload) {
  const data = payload.data || payload;
  const participants = [];
  for (const attendee of Array.isArray(data.meeting_attendees) ? data.meeting_attendees : []) {
    participants.push({ name: attendee.displayName || attendee.name, email: attendee.email, role: 'unknown' });
  }
  for (const email of Array.isArray(data.participants) ? data.participants : []) {
    participants.push({ name: null, email, role: 'unknown' });
  }
  if (data.organizer_email) participants.push({ name: null, email: data.organizer_email, role: 'internal' });
  const sentences = Array.isArray(data.sentences) ? data.sentences : [];
  const duration = toFiniteOrNull(data.duration);
  return {
    callId: data.id || payload.meetingId,
    title: data.title,
    startedAt: toIsoOrNull(data.date),
    durationSeconds: duration === null ? null : Math.round(duration * 60),
    url: safeHttpUrl(data.transcript_url),
    participants,
    transcript: mergeSpeakerTurns(sentences.map((s) => ({ speaker: s.speaker_name, text: s.text }))),
    summary: data.summary?.overview || data.summary?.short_summary || null,
    dealIdHint: genericDealIdHint(payload),
  };
}

export function normalizeFathomPayload(payload) {
  const participants = [];
  for (const invitee of Array.isArray(payload.calendar_invitees) ? payload.calendar_invitees : []) {
    const role = invitee.is_external === true ? 'external' : invitee.is_external === false ? 'internal' : 'unknown';
    participants.push({ name: invitee.name, email: invitee.email, role });
  }
  if (payload.recorded_by) {
    participants.push({ name: payload.recorded_by.name, email: payload.recorded_by.email, role: 'internal' });
  }
  const start = toIsoOrNull(payload.recording_start_time || payload.scheduled_start_time || payload.created_at);
  const end = toIsoOrNull(payload.recording_end_time);
  const transcript = Array.isArray(payload.transcript) ? payload.transcript : [];
  return {
    callId: payload.recording_id ?? payload.id,
    title: payload.meeting_title || payload.title,
    startedAt: start,
    durationSeconds: start && end ? Math.max(0, Math.round((Date.parse(end) - Date.parse(start)) / 1000)) : null,
    url: safeHttpUrl(payload.share_url || payload.url),
    participants,
    transcript: mergeSpeakerTurns(transcript.map((t) => ({ speaker: t.speaker?.display_name, text: t.text }))),
    summary: payload.default_summary?.markdown_formatted || null,
    dealIdHint: genericDealIdHint(payload),
  };
}

export function normalizeTranscriptPayload(payload, { sourceHint = null, internalDomains = [] } = {}) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new NormalizationError('invalid_payload', 'Webhook payload must be a JSON object');
  }
  const source = detectTranscriptSource(payload, sourceHint);
  if (!source) {
    throw new NormalizationError('unknown_source', 'Could not detect Gong, Fireflies.ai or Fathom payload shape');
  }
  const base =
    source === 'gong'
      ? normalizeGongPayload(payload)
      : source === 'fireflies'
        ? normalizeFirefliesPayload(payload)
        : normalizeFathomPayload(payload);

  const internal = new Set(internalDomains.map((d) => String(d).trim().toLowerCase()).filter(Boolean));
  const byKey = new Map();
  for (const raw of base.participants) {
    const email = normalizeEmail(raw.email);
    const domain = email ? email.split('@')[1] : null;
    let role = raw.role || 'unknown';
    if (domain && internal.has(domain)) role = 'internal';
    else if (role === 'unknown' && domain) role = 'external';
    const name = sanitizeString(raw.name, 120) || (email ? email.split('@')[0] : 'Unknown participant');
    const key = email || name.toLowerCase();
    const existing = byKey.get(key);
    if (existing) {
      if (existing.name === 'Unknown participant' || existing.name === email?.split('@')[0]) existing.name = name;
      if (existing.role === 'unknown') existing.role = role;
    } else {
      byKey.set(key, { name, email, role });
    }
  }
  const participants = [...byKey.values()];
  const externals = participants.filter((p) => p.role === 'external' && p.email);
  const externalEmails = [...new Set(externals.map((p) => p.email))];
  const externalDomains = [
    ...new Set(externals.map((p) => p.email.split('@')[1]).filter((d) => !isFreeEmailDomain(d) && !internal.has(d))),
  ];

  const transcript = String(base.transcript || '').trim();
  const summary = base.summary ? String(base.summary).trim() : null;
  if (!transcript && !summary) {
    throw new NormalizationError('empty_content', 'Payload contains neither a transcript nor a summary');
  }
  const callId = sanitizeString(base.callId, 128);
  if (!callId) throw new NormalizationError('missing_call_id', 'Payload is missing a call/recording identifier');

  return {
    schemaVersion: 1,
    source,
    callId,
    title: sanitizeString(base.title, 250) || 'Untitled call',
    startedAt: base.startedAt,
    durationSeconds: base.durationSeconds,
    url: base.url,
    participants,
    externalDomains,
    externalEmails,
    transcript,
    summary,
    crm: { dealIdHint: base.dealIdHint || null },
  };
}
