/**
 * Stage-gate evaluation: compares extracted MEDDIC/BANT fields against the
 * qualification rules for the deal's current HubSpot stage and the stage it is
 * trying to enter next, then flags missing, low-confidence or ungrounded criteria.
 */
import { QUALIFICATION_FIELDS, QUALIFICATION_FIELD_KEYS } from '../extractors/meddicBantExtractor.js';

const PROPERTY_NAME_RE = /^[a-z][a-z0-9_]*$/;

function isUnitInterval(value) {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 1;
}

/** Structural validation for config/qualification-rules*.json. Returns { valid, errors }. */
export function validateQualificationRules(rules) {
  const errors = [];
  if (!rules || typeof rules !== 'object') return { valid: false, errors: ['rules must be an object'] };
  if (rules.version !== 1) errors.push('version must be 1');
  if (!isUnitInterval(rules.defaults?.minConfidence)) errors.push('defaults.minConfidence must be a number between 0 and 1');
  const pipelines = rules.pipelines && typeof rules.pipelines === 'object' ? rules.pipelines : null;
  if (!pipelines || !Object.keys(pipelines).length) errors.push('pipelines must define at least one pipeline');
  if (rules.defaultPipelineId && pipelines && !pipelines[rules.defaultPipelineId]) {
    errors.push(`defaultPipelineId "${rules.defaultPipelineId}" is not defined in pipelines`);
  }
  for (const [pipelineId, pipeline] of Object.entries(pipelines || {})) {
    const stages = pipeline?.stages && typeof pipeline.stages === 'object' ? pipeline.stages : {};
    if (!Object.keys(stages).length) errors.push(`pipelines.${pipelineId}.stages must not be empty`);
    for (const stageId of pipeline?.stageOrder || []) {
      if (!stages[stageId]) errors.push(`pipelines.${pipelineId}.stageOrder references unknown stage "${stageId}"`);
    }
    for (const stageId of pipeline?.terminalStages || []) {
      if (!stages[stageId]) errors.push(`pipelines.${pipelineId}.terminalStages references unknown stage "${stageId}"`);
    }
    for (const [stageId, stage] of Object.entries(stages)) {
      const where = `pipelines.${pipelineId}.stages.${stageId}`;
      if (!Array.isArray(stage.requiredToEnter)) errors.push(`${where}.requiredToEnter must be an array`);
      for (const key of stage.requiredToEnter || []) {
        if (!QUALIFICATION_FIELD_KEYS.includes(key)) errors.push(`${where}.requiredToEnter has unknown field "${key}"`);
      }
      if (stage.minConfidence !== undefined && !isUnitInterval(stage.minConfidence)) {
        errors.push(`${where}.minConfidence must be between 0 and 1`);
      }
    }
  }
  for (const [key, override] of Object.entries(rules.fieldOverrides || {})) {
    if (!QUALIFICATION_FIELD_KEYS.includes(key)) errors.push(`fieldOverrides has unknown field "${key}"`);
    if (override.minConfidence !== undefined && !isUnitInterval(override.minConfidence)) {
      errors.push(`fieldOverrides.${key}.minConfidence must be between 0 and 1`);
    }
  }
  for (const [key, weight] of Object.entries(rules.scoringWeights || {})) {
    if (!QUALIFICATION_FIELD_KEYS.includes(key)) errors.push(`scoringWeights has unknown field "${key}"`);
    if (typeof weight !== 'number' || weight < 0) errors.push(`scoringWeights.${key} must be a non-negative number`);
  }
  const map = rules.hubspotPropertyMap;
  if (!map?.fields) {
    errors.push('hubspotPropertyMap.fields is required');
  } else {
    for (const key of QUALIFICATION_FIELD_KEYS) {
      const entry = map.fields[key];
      if (!entry) {
        errors.push(`hubspotPropertyMap.fields.${key} is required`);
        continue;
      }
      for (const prop of ['value', 'confidence']) {
        if (!PROPERTY_NAME_RE.test(String(entry[prop] || ''))) {
          errors.push(`hubspotPropertyMap.fields.${key}.${prop} must be a lowercase HubSpot internal property name`);
        }
      }
    }
    for (const [name, prop] of Object.entries(map.summary || {})) {
      if (!PROPERTY_NAME_RE.test(String(prop || ''))) errors.push(`hubspotPropertyMap.summary.${name} is not a valid property name`);
    }
  }
  if (rules.propertyWrite?.minConfidenceToWrite !== undefined && !isUnitInterval(rules.propertyWrite.minConfidenceToWrite)) {
    errors.push('propertyWrite.minConfidenceToWrite must be between 0 and 1');
  }
  return { valid: errors.length === 0, errors };
}

export function computeQualificationScore(extraction, rules) {
  const weights = rules?.scoringWeights || {};
  let total = 0;
  let earned = 0;
  for (const key of QUALIFICATION_FIELD_KEYS) {
    const weight = typeof weights[key] === 'number' ? weights[key] : 10;
    const field = extraction?.fields?.[key];
    total += weight;
    if (!field || field.status === 'missing') continue;
    const statusFactor = field.status === 'identified' ? 1 : 0.5;
    const groundingFactor = field.grounded ? 1 : 0.5;
    earned += weight * statusFactor * groundingFactor * field.confidence;
  }
  return total > 0 ? Math.round((earned / total) * 100) : 0;
}

function resolveMinConfidence(rules, stage, key) {
  const override = rules.fieldOverrides?.[key]?.minConfidence;
  const stageMin = stage?.minConfidence;
  const base = rules.defaults.minConfidence;
  return Math.max(base, typeof stageMin === 'number' ? stageMin : 0, typeof override === 'number' ? override : 0);
}

function assessStageRequirements(extraction, rules, stageId, stage) {
  const requireEvidence = rules.defaults.requireGroundedEvidence !== false;
  const issues = [];
  const satisfied = [];
  for (const key of stage.requiredToEnter || []) {
    const label = QUALIFICATION_FIELDS.find((f) => f.key === key).label;
    const field = extraction?.fields?.[key];
    const minConfidence = resolveMinConfidence(rules, stage, key);
    const confidence = field?.confidence ?? 0;
    let reason = null;
    if (!field || field.status === 'missing' || !field.value) reason = 'missing';
    else if (confidence < minConfidence) reason = 'low_confidence';
    else if (requireEvidence && !field.grounded) reason = 'ungrounded';
    if (reason) issues.push({ field: key, label, reason, confidence, minConfidence });
    else satisfied.push(key);
  }
  return { stageId, label: stage.label || stageId, passed: issues.length === 0, issues, satisfied };
}

/** Works out which pipeline/stage rules apply and which stage the deal would enter next. */
export function resolveStagePlan(rules, { pipelineId, currentStageId, targetStageId }) {
  const resolvedPipelineId = rules.pipelines[pipelineId] ? pipelineId : rules.defaultPipelineId || 'default';
  const pipeline = rules.pipelines[resolvedPipelineId];
  if (!pipeline) return { pipelineId: resolvedPipelineId, pipeline: null, reason: 'unknown_pipeline' };
  const usedFallbackPipeline = resolvedPipelineId !== pipelineId;
  const current = pipeline.stages[currentStageId] || null;
  if (!current && !targetStageId) {
    return { pipelineId: resolvedPipelineId, pipeline, usedFallbackPipeline, reason: 'unknown_stage' };
  }
  if ((pipeline.terminalStages || []).includes(currentStageId) && !targetStageId) {
    return { pipelineId: resolvedPipelineId, pipeline, usedFallbackPipeline, reason: 'deal_closed' };
  }
  let nextStageId = targetStageId || null;
  if (!nextStageId) {
    const order = pipeline.stageOrder || [];
    const idx = order.indexOf(currentStageId);
    nextStageId = idx >= 0 && idx < order.length - 1 ? order[idx + 1] : null;
  }
  const target = nextStageId ? pipeline.stages[nextStageId] || null : null;
  if (nextStageId && !target) {
    return { pipelineId: resolvedPipelineId, pipeline, usedFallbackPipeline, reason: 'unknown_target_stage' };
  }
  return {
    pipelineId: resolvedPipelineId,
    pipeline,
    usedFallbackPipeline,
    reason: null,
    currentStageId,
    current,
    targetStageId: nextStageId,
    target,
  };
}

export function evaluateStageGate({ extraction, rules, pipelineId, currentStageId, targetStageId = null }) {
  const score = computeQualificationScore(extraction, rules);
  const plan = resolveStagePlan(rules, { pipelineId, currentStageId, targetStageId });
  const base = {
    pipelineId: plan.pipelineId,
    pipelineLabel: plan.pipeline?.label || plan.pipelineId,
    usedFallbackPipeline: Boolean(plan.usedFallbackPipeline),
    currentStageId: currentStageId || null,
    score,
  };
  if (plan.reason) {
    const alertUnknown = rules.defaults.alertOnUnknownStage !== false && plan.reason !== 'deal_closed';
    return {
      ...base,
      evaluated: false,
      reason: plan.reason,
      current: null,
      target: null,
      passed: false,
      blockAdvance: false,
      alert: { slack: alertUnknown, mentionOwner: false, severity: 'info' },
    };
  }
  const current = plan.current ? assessStageRequirements(extraction, rules, plan.currentStageId, plan.current) : null;
  const target = plan.target ? assessStageRequirements(extraction, rules, plan.targetStageId, plan.target) : null;
  const passed = (target ? target.passed : true) && (current ? current.passed : true);
  const targetSlack = plan.target?.slack || {};
  const currentSlack = plan.current?.slack || {};
  const alertOnTarget = Boolean(target && !target.passed && targetSlack.alertOnMissing !== false);
  const alertOnCurrent = Boolean(current && !current.passed && currentSlack.alertOnMissing !== false);
  return {
    ...base,
    evaluated: true,
    reason: null,
    current,
    target,
    passed,
    blockAdvance: Boolean(target && !target.passed && plan.target.blockAdvance !== false),
    alert: {
      slack: alertOnTarget || alertOnCurrent,
      mentionOwner: Boolean((alertOnTarget && targetSlack.mentionOwner) || (alertOnCurrent && currentSlack.mentionOwner)),
      severity: (alertOnTarget ? targetSlack.severity : currentSlack.severity) || 'warning',
    },
  };
}
