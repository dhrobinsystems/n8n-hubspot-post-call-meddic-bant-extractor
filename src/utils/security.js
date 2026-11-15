/**
 * Security utilities: webhook HMAC-SHA256 verification, PII redaction,
 * transcript truncation and output escaping.
 *
 * Pure functions only. This module is also embedded verbatim into the n8n Code
 * nodes by scripts/build-n8n-workflow.js, so every top-level name in src/ must
 * stay unique and top-level declarations must start at column 0.
 */
import crypto from 'node:crypto';

const PLACEHOLDER_RE = /^(?:|your_[a-z0-9_]*_here|changeme|change_me|placeholder|x{3,})$/i;

export class SafetyInterlockError extends Error {
  constructor(code, message) {
    super(message || code);
    this.name = 'SafetyInterlockError';
    this.code = code;
  }
}

/** True when a configuration value is empty or still one of the dummy placeholders. */
export function isPlaceholder(value) {
  if (value === undefined || value === null) return true;
  return PLACEHOLDER_RE.test(String(value).trim());
}

export function computeHmacSha256Hex(secret, payload) {
  return crypto.createHmac('sha256', String(secret)).update(String(payload), 'utf8').digest('hex');
}

/** When a timestamp header is used, the signed payload is `${timestamp}.${rawBody}` (replay protection). */
export function buildSignedPayload(rawBody, timestamp) {
  return timestamp ? `${timestamp}.${rawBody}` : String(rawBody);
}

export function signWebhookPayload({ secret, rawBody, timestamp }) {
  return `sha256=${computeHmacSha256Hex(secret, buildSignedPayload(rawBody, timestamp))}`;
}

function parseSignatureCandidates(header) {
  return String(header)
    .split(',')
    .map((part) => part.trim())
    .filter(Boolean)
    .map((part) => {
      const match = part.match(/^(?:sha256|v1)[=:](.+)$/i);
      return (match ? match[1] : part).trim().toLowerCase();
    })
    .filter((candidate) => /^[0-9a-f]{64}$/.test(candidate));
}

export function safeHexEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  return crypto.timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
}

/**
 * Verifies `sha256=<hex>` (or bare hex, or comma-separated candidates) against
 * HMAC-SHA256(secret, rawBody) or HMAC-SHA256(secret, `${timestamp}.${rawBody}`).
 * Comparison is constant-time.
 */
export function verifyWebhookSignature({
  rawBody,
  signatureHeader,
  timestampHeader,
  secret,
  toleranceSeconds = 300,
  requireTimestamp = false,
  now = Date.now(),
}) {
  if (typeof rawBody !== 'string') return { valid: false, reason: 'raw_body_not_string' };
  if (!secret) return { valid: false, reason: 'secret_not_configured' };
  if (!signatureHeader) return { valid: false, reason: 'missing_signature' };
  const timestamp = timestampHeader ? String(timestampHeader).trim() : '';
  if (!timestamp && requireTimestamp) return { valid: false, reason: 'missing_timestamp' };
  if (timestamp) {
    if (!/^\d{9,13}$/.test(timestamp)) return { valid: false, reason: 'invalid_timestamp' };
    const timestampMs = timestamp.length >= 13 ? Number(timestamp) : Number(timestamp) * 1000;
    if (Math.abs(now - timestampMs) > toleranceSeconds * 1000) {
      return { valid: false, reason: 'timestamp_outside_tolerance' };
    }
  }
  const candidates = parseSignatureCandidates(signatureHeader);
  if (!candidates.length) return { valid: false, reason: 'malformed_signature' };
  const expected = computeHmacSha256Hex(secret, buildSignedPayload(rawBody, timestamp));
  return candidates.some((candidate) => safeHexEqual(candidate, expected))
    ? { valid: true, reason: 'ok' }
    : { valid: false, reason: 'signature_mismatch' };
}

function countDigits(value) {
  return String(value).replace(/\D/g, '').length;
}

export function luhnValid(value) {
  const digits = String(value).replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let doubleIt = false;
  for (let i = digits.length - 1; i >= 0; i -= 1) {
    let d = Number(digits[i]);
    if (doubleIt) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    doubleIt = !doubleIt;
  }
  return sum % 10 === 0;
}

const PII_PATTERNS = [
  {
    type: 'secret',
    re: /\b(?:sk-[A-Za-z0-9_-]{16,}|pat-[a-z0-9]{2,4}-[A-Za-z0-9-]{16,}|xox[abprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16})\b/g,
    token: '[REDACTED_SECRET]',
  },
  { type: 'email', re: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, token: '[REDACTED_EMAIL]' },
  { type: 'iban', re: /\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){3,7}(?: ?[A-Z0-9]{1,3})?\b/g, token: '[REDACTED_IBAN]' },
  { type: 'card', re: /\b(?:\d[ -]?){12,18}\d\b/g, token: '[REDACTED_CARD]', check: luhnValid },
  { type: 'ssn', re: /\b\d{3}-\d{2}-\d{4}\b/g, token: '[REDACTED_SSN]' },
  {
    type: 'phone',
    re: /(?:\+\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)[\s.-]?)?\d{2,4}[\s.-]\d{3,4}[\s.-]?\d{3,4}\b/g,
    token: '[REDACTED_PHONE]',
    check: (match) => countDigits(match) >= 10 && countDigits(match) <= 15,
  },
];

/** Replaces emails, phone numbers, card numbers, SSNs, IBANs and API-key-like strings with tokens. */
export function redactPii(text) {
  let output = String(text ?? '');
  const redactions = {};
  for (const pattern of PII_PATTERNS) {
    output = output.replace(pattern.re, (match) => {
      if (pattern.check && !pattern.check(match)) return match;
      redactions[pattern.type] = (redactions[pattern.type] || 0) + 1;
      return pattern.token;
    });
  }
  return { text: output, redactions };
}

export function stripControlChars(value) {
  return String(value ?? '').replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '');
}

/** Single-line clean string with a hard length cap. */
export function sanitizeString(value, maxLength = 500) {
  if (value === undefined || value === null) return '';
  const clean = stripControlChars(String(value)).replace(/\s+/g, ' ').trim();
  return clean.length > maxLength ? `${clean.slice(0, Math.max(0, maxLength - 1))}…` : clean;
}

/** Keeps the head and the tail of long text (pricing and next steps tend to come late in a call). */
export function truncateMiddle(text, maxChars, headRatio = 0.7) {
  const value = String(text ?? '');
  if (!maxChars || value.length <= maxChars) return { text: value, truncated: false, removedChars: 0 };
  const removed = value.length - maxChars;
  const marker = `\n[... ${removed} characters truncated before LLM submission ...]\n`;
  const budget = Math.max(0, maxChars - marker.length);
  const head = Math.floor(budget * headRatio);
  const tail = budget - head;
  return {
    text: `${value.slice(0, head)}${marker}${tail > 0 ? value.slice(value.length - tail) : ''}`,
    truncated: true,
    removedChars: removed,
  };
}

/** Cleans, redacts and truncates a transcript before it is sent to any LLM. */
export function sanitizeTranscript(text, { maxChars = 60000, redact = true } = {}) {
  const original = String(text ?? '');
  let output = stripControlChars(original)
    .replace(/\r\n?/g, '\n')
    .replace(/[ \t]+\n/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
  let redactions = {};
  if (redact) {
    const result = redactPii(output);
    output = result.text;
    redactions = result.redactions;
  }
  const truncated = truncateMiddle(output, maxChars);
  return {
    text: truncated.text,
    redactions,
    truncated: truncated.truncated,
    originalLength: original.length,
    finalLength: truncated.text.length,
  };
}

export function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
