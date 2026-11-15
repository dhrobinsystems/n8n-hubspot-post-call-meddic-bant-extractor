# ⚠️ Disclaimer & Liability Limitation

**Use at your own risk.** The code, workflows, and scripts provided in this repository (`n8n-hubspot-post-call-meddic-bant-extractor`) are for educational and architectural demonstration purposes. I publish them as a reference implementation from dhRobin Systems, not as a managed product or a service.

## No Liability

The author and dhRobin Systems assume no responsibility or liability for any direct, indirect, incidental, special, exemplary, or consequential damages (including, without limitation, lost revenue, lost deals, corrupted or overwritten CRM data, missed or incorrect stage changes, regulatory penalties, or business interruption) resulting from the use, misuse, or deployment of these scripts, however caused and on any theory of liability, even if advised of the possibility of such damage.

## No Warranty

All software, n8n JSON blueprints, and JavaScript modules are provided "AS IS" without warranty of any kind, express or implied, including but not limited to merchantability, fitness for a particular purpose, or non-infringement. I do not warrant that the code is error-free, secure, compatible with any specific version of n8n, HubSpot, Gong, Fireflies.ai, Fathom, OpenAI, Anthropic, or Slack, or that vendor APIs and webhook payloads will keep the shapes this repository expects.

## Production Testing Required

Always test thoroughly in an isolated staging environment (for example a HubSpot developer test account or sandbox, and a dedicated Slack test channel) with `SANDBOX_MODE=true` and `DRY_RUN=true` enabled before connecting live HubSpot credentials. Review the dry-run output, the intercepted property updates, and the generated notes before turning `DRY_RUN` off. Treat every deal property overwrite and every logged note as permanent CRM history: HubSpot property history and notes are not reliably reversible by this project.

## AI-Generated Output

MEDDIC and BANT values are produced by a large language model (or, in mock mode, by keyword heuristics). They can be incomplete, misattributed, or wrong even when evidence quotes are present and verified against the transcript. Extracted fields, confidence scores, and stage-gate verdicts are decision support only. They are not a substitute for the judgement of the deal owner or sales leadership, and they must not be the sole basis for forecasting, compensation, or contractual decisions.

## Third-Party APIs & Compliance

Users are solely responsible for complying with the terms of service, rate limits, data privacy regulations (GDPR, UK GDPR, CCPA/CPRA and any other applicable law), and security policies of HubSpot, Gong, Fireflies.ai, Fathom, OpenAI, Anthropic, Slack, and any other connected service. That includes:

- confirming that every recorded call has the notice and consent required in each participant's jurisdiction, including all-party consent where it applies;
- confirming a lawful basis for sending call transcripts to an LLM provider, and reviewing that provider's data retention, training, and sub-processor terms;
- configuring PII redaction and transcript truncation appropriately, and understanding that pattern-based redaction will not catch every piece of personal or confidential data;
- restricting who can see n8n execution data, server logs, HubSpot notes, and Slack channels that receive qualification content;
- honouring data subject requests (access, correction, deletion) across every system this workflow writes to;
- reviewing every automated property overwrite and every stage-gate alert.

## Security

Webhook signature verification, sandbox interlocks, and redaction guards reduce risk but do not eliminate it. You are responsible for protecting secrets, rotating credentials, restricting network exposure of the webhook endpoint, and keeping n8n, Node.js, and all dependencies patched.

## Not Professional Advice

Nothing in this repository is legal, compliance, privacy, or financial advice. Consult qualified professionals for your jurisdiction and use case.

---

License: MIT © 2026 DH Robin (dhRobin Systems). See [LICENSE](./LICENSE).
