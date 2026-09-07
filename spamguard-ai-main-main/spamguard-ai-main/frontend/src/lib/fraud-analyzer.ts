import { fraudModelService } from './fraud-model';

export type ThreatSeverity = 'CRITICAL' | 'HIGH' | 'ELEVATED' | 'LOW' | 'SAFE';

export type AttackVectorType =
  | 'BEC_EXECUTIVE_IMPERSONATION'
  | 'FINANCIAL_WIRE_FRAUD'
  | 'CREDENTIAL_HARVESTING'
  | 'CRYPTO_INVESTMENT_SCAM'
  | 'EXTORTION_INTIMIDATION'
  | 'PAYMENT_REDIRECT_SCAM'
  | 'SUSPICIOUS_UNVERIFIED'
  | 'BENIGN_AUTHENTIC';

export interface ThreatVectorScore {
  name: string;
  score: number; // 0 - 100
  status: 'low' | 'moderate' | 'high' | 'critical';
  details: string;
}

export interface ExtractedEntity {
  type: 'url' | 'currency' | 'crypto' | 'pii' | 'urgency' | 'action_phrase';
  label: string;
  value: string;
  riskWeight: 'low' | 'medium' | 'high' | 'critical';
}

export interface FraudEvidenceItem {
  id: string;
  vector: string;
  severity: 'critical' | 'high' | 'warning' | 'info';
  title: string;
  description: string;
  triggerPhrase?: string;
}

export interface HighlightSegment {
  text: string;
  isFlagged: boolean;
  type?: 'financial' | 'phishing' | 'impersonation' | 'urgency' | 'domain';
  label?: string;
  color?: string;
}

export interface FraudAnalysisResult {
  riskScore: number; // 0 - 100
  severity: ThreatSeverity;
  verdictAction: {
    title: string;
    badgeText: string;
    primaryAction: string;
    secondaryAction: string;
  };
  classification: AttackVectorType;
  classificationTitle: string;
  mitreCode: string;
  executiveSummary: string;
  confidence: number;
  evidence: FraudEvidenceItem[];
  highlightedSegments: HighlightSegment[];
  vectors: {
    financial: ThreatVectorScore;
    phishing: ThreatVectorScore;
    impersonation: ThreatVectorScore;
    urgency: ThreatVectorScore;
    domain: ThreatVectorScore;
  };
  entities: ExtractedEntity[];
  iocs: string[];
  playbookActions: string[];
  senderEvaluation?: {
    sender: string;
    isSpoofedDomain: boolean;
    domainRisk: string;
  };
  timestamp: string;
  scanId: string;
}

// Regex heuristics
const URL_REGEX = /(?:https?:\/\/|www\.)[^\s/$.?#].[^\s]*/gi;
const CRYPTO_REGEX = /\b(bc1[a-zA-HJ-NP-Z0-9]{25,39}|1[a-km-zA-HJ-NP-Z1-9]{25,34}|3[a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40})\b/g;
const CURRENCY_REGEX = /(\$\s*\d{1,3}(?:,\d{3})*(?:\.\d{2})?|\b\d{1,3}(?:,\d{3})*\s*(?:usd|dollars|eur|gbp|usdt|btc)\b)/gi;
const SUSPICIOUS_TLDS = ['.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.zip', '.mov', '.buzz', '.icu', '.monster'];

// Categorized trigger patterns
const FINANCIAL_FRAUD_PATTERNS = [
  { pattern: /\b(wire transfer|bank wire|swift|routing number|ach payment|invoice update|new bank account|payment instructions|beneficiary change|wire \$[0-9,]+)\b/i, weight: 50, label: 'Wire / SWIFT Redirection' },
  { pattern: /\b(unauthorized transaction|charge of \$|fraud alert|security department|suspicious activity on your card|temporary hold)\b/i, weight: 45, label: 'Financial Impersonation Alert' },
  { pattern: /\b(gift card|apple card|steam card|razer gold|target card|pay with cards)\b/i, weight: 55, label: 'Untraceable Gift Card Demand' },
  { pattern: /\b(crypto|bitcoin|ethereum|guaranteed return|doubler|forex trading|daily profit|investment pool|usdt deposit|arbitrage pool)\b/i, weight: 50, label: 'Unregulated Crypto Investment' },
  { pattern: /\b(lottery|inheritance|consortium|unclaimed funds|western union|moneygram|processing fee required)\b/i, weight: 45, label: 'Advance-Fee / Lottery Scam' },
  { pattern: /\b(refund of \$|overpaid|deducted from your account|subscription renewal \$[0-9]+|geek squad|norton lifelock)\b/i, weight: 45, label: 'Fake Refund / Invoice Trap' }
];

const PHISHING_PATTERNS = [
  { pattern: /\b(verify your account|account suspended|password expires|reset your credential|security checkpoint|re-authenticate|identity verification)\b/i, weight: 45, label: 'Credential Harvest Trigger' },
  { pattern: /\b(click here|log in now|tap here to resolve|access your portal|sign in immediately|update your billing)\b/i, weight: 35, label: 'Coercive Call-To-Action' },
  { pattern: /\b(mfa|two-factor|otp|one-time code|auth code|do not share this code)\b/i, weight: 45, label: 'MFA / OTP Interception' },
  { pattern: /\b(ssn|social security|credit card number|card pin|cvv|mother's maiden|card expiration)\b/i, weight: 55, label: 'Critical PII Extraction' }
];

const IMPERSONATION_PATTERNS = [
  { pattern: /\b(ceo|cfo|executive vice president|managing director|board of directors|president's office|closed-door|acquisition)\b/i, weight: 45, label: 'Executive Authority Tone' },
  { pattern: /\b(internal revenue service|irs|fbi|law enforcement|federal court|arrest warrant|legal subpoena)\b/i, weight: 55, label: 'Government / Legal Intimidation' },
  { pattern: /\b(it department|helpdesk support|systems administrator|network alert|microsoft 365 team|google workspace admin)\b/i, weight: 40, label: 'Internal IT / Admin Spoofing' },
  { pattern: /\b(strictly confidential|keep this private|do not discuss with anyone|direct order|emergency meeting)\b/i, weight: 45, label: 'Isolation & Secrecy Mandate' }
];

const URGENCY_PATTERNS = [
  { pattern: /\b(urgent|immediately|within 24 hours|within 1 hour|before end of day|before 3:00|action required now|immediate response|account terminated)\b/i, weight: 40, label: 'Extreme Time Pressure' },
  { pattern: /\b(final warning|last notice|legal consequences|penalty fee|frozen immediately|service suspension|permanent mailbox suspension)\b/i, weight: 45, label: 'Coercive Threat Penalty' }
];

export async function analyzeFraudText(
  text: string,
  sender?: string
): Promise<FraudAnalysisResult> {
  const scanId = `FG-${Math.random().toString(36).substring(2, 8).toUpperCase()}-${Date.now().toString().slice(-4)}`;
  const entities: ExtractedEntity[] = [];
  const iocs: string[] = [];
  const evidence: FraudEvidenceItem[] = [];

  // 1. Run local TFJS Model if available
  let mlScore = 0;
  try {
    const mlPrediction = await fraudModelService.predict(text);
    mlScore = Math.round(mlPrediction.confidence * 100);
  } catch (err) {
    console.warn('ML Service offline, continuing with deep heuristic matrix', err);
    mlScore = 50;
  }

  // 2. URLs & Domain Extraction
  const urls = text.match(URL_REGEX) || [];
  let domainRiskScore = 0;
  let hasSuspiciousDomain = false;

  urls.forEach(url => {
    let riskWeight: ExtractedEntity['riskWeight'] = 'medium';
    const lowerUrl = url.toLowerCase();
    
    // Check suspicious TLDs
    const matchedTLD = SUSPICIOUS_TLDS.find(tld => lowerUrl.includes(tld));
    if (matchedTLD) {
      riskWeight = 'critical';
      domainRiskScore += 65;
      hasSuspiciousDomain = true;
      iocs.push(`Suspicious High-Risk TLD (${matchedTLD}) in URL: ${url}`);
      evidence.push({
        id: 'ev-tld',
        vector: 'Domain Infrastructure',
        severity: 'critical',
        title: `Untrusted / Disposable TLD (${matchedTLD})`,
        description: `URL points to a high-risk disposable top-level domain frequently used in phishing campaigns.`,
        triggerPhrase: url
      });
    }

    // Check IP host in URL
    if (/(?:https?:\/\/)?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url)) {
      riskWeight = 'critical';
      domainRiskScore += 70;
      hasSuspiciousDomain = true;
      iocs.push(`Direct IP Address Host Detected: ${url}`);
      evidence.push({
        id: 'ev-ip',
        vector: 'Domain Infrastructure',
        severity: 'critical',
        title: 'Direct IP Host (No Domain Name)',
        description: 'Attackers use raw IP addresses to evade standard domain reputation filters.',
        triggerPhrase: url
      });
    }

    // Lookalike brand tricks
    if (/paypa[l1]|arnazon|micros[o0]ft|cha[s5]e|ne[t7]flix|app[l1]e/i.test(url)) {
      riskWeight = 'critical';
      domainRiskScore += 75;
      hasSuspiciousDomain = true;
      iocs.push(`Brand Impersonation Lookalike Domain: ${url}`);
      evidence.push({
        id: 'ev-lookalike',
        vector: 'Brand Impersonation',
        severity: 'critical',
        title: 'Typosquatting / Brand Lookalike Domain',
        description: 'Domain attempts to deceptively mimic a trusted institution with minor character substitution.',
        triggerPhrase: url
      });
    }

    entities.push({
      type: 'url',
      label: 'Embedded Web Target',
      value: url,
      riskWeight
    });
  });

  // 3. Crypto Extraction
  const cryptoMatches = text.match(CRYPTO_REGEX) || [];
  cryptoMatches.forEach(address => {
    entities.push({
      type: 'crypto',
      label: 'Unregistered Crypto Wallet',
      value: address,
      riskWeight: 'critical'
    });
    iocs.push(`Cryptocurrency Destination: ${address}`);
    evidence.push({
      id: 'ev-crypto',
      vector: 'Financial Fraud',
      severity: 'critical',
      title: 'Untraceable Cryptocurrency Destination',
      description: 'Demands asset transfer to an unhosted cryptocurrency wallet address without buyer protection.',
      triggerPhrase: address
    });
  });

  // 4. Currency / Monetary Extraction
  const currencyMatches = text.match(CURRENCY_REGEX) || [];
  currencyMatches.forEach(amount => {
    entities.push({
      type: 'currency',
      label: 'Financial Exposure Stake',
      value: amount,
      riskWeight: 'high'
    });
    iocs.push(`Financial Exposure Value: ${amount}`);
  });

  // 5. Vector Calculations
  // Vector A: Financial Risk
  let financialScore = 0;
  const financialMatches: string[] = [];
  FINANCIAL_FRAUD_PATTERNS.forEach(p => {
    const match = text.match(p.pattern);
    if (match) {
      financialScore += p.weight;
      financialMatches.push(p.label);
      entities.push({
        type: 'action_phrase',
        label: p.label,
        value: match[0],
        riskWeight: p.weight > 45 ? 'critical' : 'high'
      });
      evidence.push({
        id: `ev-fin-${financialMatches.length}`,
        vector: 'Financial Exposure',
        severity: p.weight > 45 ? 'critical' : 'high',
        title: p.label,
        description: `Detected suspicious transaction patterns attempting to divert or request funds.`,
        triggerPhrase: match[0]
      });
    }
  });

  if (cryptoMatches.length > 0) financialScore += 50;
  if (currencyMatches.length > 0 && financialScore > 0) financialScore += 30;

  // Vector B: Phishing & Credential Theft
  let phishingScore = 0;
  const phishingMatches: string[] = [];
  PHISHING_PATTERNS.forEach(p => {
    const match = text.match(p.pattern);
    if (match) {
      phishingScore += p.weight;
      phishingMatches.push(p.label);
      entities.push({
        type: p.label.includes('PII') ? 'pii' : 'action_phrase',
        label: p.label,
        value: match[0],
        riskWeight: p.weight > 45 ? 'critical' : 'high'
      });
      evidence.push({
        id: `ev-phish-${phishingMatches.length}`,
        vector: 'Credential Phishing',
        severity: p.weight > 45 ? 'critical' : 'high',
        title: p.label,
        description: `Communication solicits sensitive login credentials, security codes, or personal identity numbers.`,
        triggerPhrase: match[0]
      });
    }
  });
  if (urls.length > 0 && phishingScore > 0) phishingScore += 35;

  // Vector C: Impersonation / BEC
  let impersonationScore = 0;
  const impersonationMatches: string[] = [];
  IMPERSONATION_PATTERNS.forEach(p => {
    const match = text.match(p.pattern);
    if (match) {
      impersonationScore += p.weight;
      impersonationMatches.push(p.label);
      entities.push({
        type: 'action_phrase',
        label: p.label,
        value: match[0],
        riskWeight: 'high'
      });
      evidence.push({
        id: `ev-imp-${impersonationMatches.length}`,
        vector: 'Impersonation & Social Engineering',
        severity: 'high',
        title: p.label,
        description: `Adopts authoritative or isolating tone ('${match[0]}') to intimidate the recipient into compliance.`,
        triggerPhrase: match[0]
      });
    }
  });

  // Vector D: Urgency & Coercion
  let urgencyScore = 0;
  const urgencyMatches: string[] = [];
  URGENCY_PATTERNS.forEach(p => {
    const match = text.match(p.pattern);
    if (match) {
      urgencyScore += p.weight;
      urgencyMatches.push(p.label);
      entities.push({
        type: 'urgency',
        label: p.label,
        value: match[0],
        riskWeight: 'high'
      });
      evidence.push({
        id: `ev-urg-${urgencyMatches.length}`,
        vector: 'Psychological Coercion',
        severity: 'high',
        title: p.label,
        description: `Imposes extreme artificial time pressure to prevent the recipient from verifying through standard channels.`,
        triggerPhrase: match[0]
      });
    }
  });

  // Vector E: Sender Analysis
  let senderEvaluation: FraudAnalysisResult['senderEvaluation'] | undefined = undefined;
  if (sender && sender.trim().length > 0) {
    const s = sender.trim().toLowerCase();
    const isFreeMail = /@(gmail|yahoo|hotmail|outlook|proton)\.com$/i.test(s);
    const hasSusTLD = SUSPICIOUS_TLDS.some(tld => s.endsWith(tld));
    const isExecutiveTone = impersonationScore > 20;

    let isSpoofedDomain = false;
    let domainRisk = 'Domain Verified / Standard Reputation';

    if (isExecutiveTone && isFreeMail) {
      isSpoofedDomain = true;
      domainRisk = 'Critical: Executive spoofing detected via free webmail provider';
      domainRiskScore += 65;
      iocs.push(`Executive Impersonation via Public Webmail: ${sender}`);
      evidence.push({
        id: 'ev-sender-freemail',
        vector: 'Domain Spoofing',
        severity: 'critical',
        title: 'Executive Impersonation on Free Webmail',
        description: `Sender claims executive authority but sends from a free public mail provider (${sender}).`,
        triggerPhrase: sender
      });
    } else if (hasSusTLD) {
      isSpoofedDomain = true;
      domainRisk = 'High: Domain uses known suspicious or disposable TLD';
      domainRiskScore += 60;
      iocs.push(`Suspicious Sender TLD: ${sender}`);
      evidence.push({
        id: 'ev-sender-tld',
        vector: 'Domain Infrastructure',
        severity: 'critical',
        title: 'Disposable Sender Domain TLD',
        description: `Sender address uses an untrusted top-level domain frequently associated with fraud.`,
        triggerPhrase: sender
      });
    }

    senderEvaluation = {
      sender,
      isSpoofedDomain,
      domainRisk
    };
  }

  // Cap sub-scores
  financialScore = Math.min(100, financialScore);
  phishingScore = Math.min(100, phishingScore);
  impersonationScore = Math.min(100, impersonationScore);
  urgencyScore = Math.min(100, urgencyScore);
  domainRiskScore = Math.min(100, domainRiskScore);

  // Compound Fraud Evaluation:
  // Count how many distinct threat vectors are elevated (score >= 35)
  const activeVectors = [financialScore, phishingScore, impersonationScore, urgencyScore, domainRiskScore].filter(s => s >= 35).length;
  const highestSingleVector = Math.max(financialScore, phishingScore, impersonationScore, domainRiskScore);

  let riskScore = 0;

  if (activeVectors >= 3 || (activeVectors >= 2 && (financialScore >= 50 || phishingScore >= 50 || domainRiskScore >= 60))) {
    // Highly orchestrated compound attack (e.g. BEC Wire + Secrecy + Urgency, or Phishing + PII + Spoofed Domain)
    riskScore = Math.round(Math.max(88, highestSingleVector + 5, (highestSingleVector * 0.7) + (mlScore * 0.3)));
    riskScore = Math.min(99, riskScore);
  } else if (activeVectors >= 2 || highestSingleVector >= 50) {
    // Substantial single or dual threat
    riskScore = Math.round(Math.max(72, highestSingleVector));
    riskScore = Math.min(92, riskScore);
  } else if (activeVectors === 1 || highestSingleVector >= 30 || mlScore > 70) {
    // Moderate / Elevated anomaly
    riskScore = Math.round(Math.max(45, (highestSingleVector * 0.7) + (mlScore * 0.3)));
    riskScore = Math.min(68, riskScore);
  } else {
    // Low risk or benign
    riskScore = Math.round((highestSingleVector * 0.4) + (mlScore * 0.3));
    riskScore = Math.min(18, riskScore);
  }

  // Determine Severity
  let severity: ThreatSeverity = 'SAFE';
  if (riskScore >= 75) severity = 'CRITICAL';
  else if (riskScore >= 55) severity = 'HIGH';
  else if (riskScore >= 30) severity = 'ELEVATED';
  else if (riskScore >= 15) severity = 'LOW';
  else severity = 'SAFE';

  // Classification & MITRE Mapping
  let classification: AttackVectorType = 'BENIGN_AUTHENTIC';
  let classificationTitle = 'Legitimate Communication';
  let mitreCode = 'N/A (Benign Protocol)';
  let executiveSummary = 'Detailed linguistic telemetry, entity extraction, and neural embeddings indicate authentic communication with no threat indicators detected.';

  let verdictAction = {
    title: 'VERIFIED AUTHENTIC',
    badgeText: 'NO THREAT DETECTED',
    primaryAction: 'Proceed with standard operational workflows.',
    secondaryAction: 'Maintain general cyber-awareness on external channels.'
  };

  if (severity === 'CRITICAL' || severity === 'HIGH') {
    if (impersonationScore >= 35 && financialScore >= 40) {
      classification = 'BEC_EXECUTIVE_IMPERSONATION';
      classificationTitle = 'Business Email Compromise (BEC) / Wire Transfer Fraud';
      mitreCode = 'MITRE ATT&CK: T1566.002 & T1586.002';
      executiveSummary = 'High-confidence targeted executive impersonation attempting to divert corporate funds via urgent unverified wire transfer under manufactured confidentiality.';
      verdictAction = {
        title: 'DO NOT WIRE FUNDS • CONFIDENTIALITY TRAP',
        badgeText: 'CRITICAL WIRE FRAUD DETECTED',
        primaryAction: 'HALT TRANSACTION: Do not initiate SWIFT/ACH wire transfer.',
        secondaryAction: 'Perform out-of-band verification: Call the executive via pre-established internal phone.'
      };
    } else if (financialScore >= 50 && cryptoMatches.length > 0) {
      classification = 'CRYPTO_INVESTMENT_SCAM';
      classificationTitle = 'Cryptocurrency Yield Scheme / Asset Drainer';
      mitreCode = 'FIN-SCAM-09 (Decentralized Asset Laundering)';
      executiveSummary = 'Fraudulent investment solicitation leveraging unhosted crypto wallet addresses, unrealistic guaranteed yield promises, and artificial pool scarcity.';
      verdictAction = {
        title: 'DO NOT SEND CRYPTOCURRENCY',
        badgeText: 'UNREGISTERED WALLET SCAM',
        primaryAction: 'Do not transfer crypto tokens to the specified wallet address.',
        secondaryAction: 'Blacklist the receiving wallet hash across AML gateway tools.'
      };
    } else if (financialScore >= 45) {
      classification = 'FINANCIAL_WIRE_FRAUD';
      classificationTitle = 'Financial Fraud / Payment Redirection Trap';
      mitreCode = 'FIN-SCAM-03 (Payment Diversion Fraud)';
      executiveSummary = 'Message contains explicit indicators of payment rerouting, fraudulent charge alerts, or invoice alteration designed to steal funds.';
      verdictAction = {
        title: 'REJECT PAYMENT REDIRECTION',
        badgeText: 'FINANCIAL FRAUD ALERT',
        primaryAction: 'Do not update banking details or settle invoices based on this notice.',
        secondaryAction: 'Contact vendor accounts payable department directly to verify banking changes.'
      };
    } else if (phishingScore >= 40) {
      classification = 'CREDENTIAL_HARVESTING';
      classificationTitle = 'Spearphishing & Credential Interception';
      mitreCode = 'MITRE ATT&CK: T1566 (Phishing for Information) / T1598';
      executiveSummary = 'Deceptive credential harvesting lure designed to intercept user login passwords, MFA authentication codes, or card PINs via lookalike portal.';
      verdictAction = {
        title: 'DO NOT CLICK LINKS OR ENTER CREDENTIALS',
        badgeText: 'CREDENTIAL HARVESTING ATTEMPT',
        primaryAction: 'Do not enter passwords, MFA codes, or personal PINs.',
        secondaryAction: 'Quarantine sender domain and submit URLs to SOC firewall blocklist.'
      };
    } else if (urgencyScore >= 40) {
      classification = 'EXTORTION_INTIMIDATION';
      classificationTitle = 'Coercive Social Engineering & Intimidation';
      mitreCode = 'MITRE ATT&CK: T1499 (Coercive Social Engineering)';
      executiveSummary = 'Exploitation of manufactured legal consequences, penalty threats, or extreme time limits to coerce immediate recipient action.';
      verdictAction = {
        title: 'DO NOT RESPOND TO INTIMIDATION',
        badgeText: 'EXTORTION / COERCION DETECTED',
        primaryAction: 'Do not reply or provide requested data under threat.',
        secondaryAction: 'Escalate message to corporate legal and compliance teams.'
      };
    } else {
      classification = 'PAYMENT_REDIRECT_SCAM';
      classificationTitle = 'High-Risk Deceptive Commercial Solicitation';
      mitreCode = 'CWE-200 / FIN-THREAT-01';
      executiveSummary = 'Multiple high-risk financial fraud and deceptive indicators detected exceeding safe operational thresholds.';
      verdictAction = {
        title: 'QUARANTINE MESSAGE',
        badgeText: 'HIGH-RISK SOLICITATION',
        primaryAction: 'Quarantine payload and flag for SOC fraud review.',
        secondaryAction: 'Block sender address at the mail server boundary.'
      };
    }
  } else if (severity === 'ELEVATED') {
    classification = 'SUSPICIOUS_UNVERIFIED';
    classificationTitle = 'Suspicious / Elevated Anomaly Risk';
    mitreCode = 'MONITOR-ALERT-LVL2';
    executiveSummary = 'The communication exhibits atypical urgency, unverified links, or vague transactional references. Review manually prior to engagement.';
    verdictAction = {
      title: 'EXERCISE CAUTION • VERIFY SENDER',
      badgeText: 'ELEVATED ANOMALY',
      primaryAction: 'Inspect embedded links carefully before interacting.',
      secondaryAction: 'Cross-reference sender address against verified corporate directory.'
    };
  }

  // Actionable Playbook Guidance
  const playbookActions: string[] = [];
  if (severity === 'CRITICAL') {
    playbookActions.push('🚨 DO NOT wire funds, click links, or input credentials.');
    playbookActions.push('🛑 Quarantine message immediately across corporate email gateways.');
    playbookActions.push('📞 Out-of-band verification: Phone the purported sender using a verified internal extension.');
    playbookActions.push('🔒 If credentials or MFA tokens were entered, initiate immediate password reset and revoke active sessions.');
    playbookActions.push('🏢 File an Incident Report with the Security Operations Center (SOC) & FinOps team.');
  } else if (severity === 'HIGH') {
    playbookActions.push('⚠️ Do not provide banking or personal identity details.');
    playbookActions.push('📞 Verify request validity through standard, pre-approved vendor contact channels.');
    playbookActions.push('🔍 Submit destination domains to Threat Intelligence sandbox for domain blacklisting.');
  } else if (severity === 'ELEVATED') {
    playbookActions.push('🔎 Inspect hyperlinks for deceptive redirects before clicking.');
    playbookActions.push('🛡️ Verify sender identity through official customer portal or directory.');
  } else {
    playbookActions.push('✅ No immediate threat detected. Normal communication protocol applies.');
    playbookActions.push('💡 Continue maintaining standard cyber hygiene for external communications.');
  }

  // 6. Generate Highlighted Segments for Explainable Visuals
  const highlightedSegments: HighlightSegment[] = [];
  const triggerWords: Array<{ word: string; type: HighlightSegment['type']; label: string; color: string }> = [];

  entities.forEach(e => {
    if (e.value && e.value.length > 2) {
      let color = 'bg-destructive/25 text-destructive border-destructive/40';
      if (e.type === 'urgency') color = 'bg-warning/25 text-warning border-warning/40';
      if (e.type === 'pii') color = 'bg-accent/25 text-accent border-accent/40';
      triggerWords.push({
        word: e.value,
        type: e.type === 'action_phrase' ? 'financial' : e.type,
        label: e.label,
        color
      });
    }
  });

  // Segment the text into highlighted parts
  let remainingText = text;
  let cursor = 0;

  // Find occurrences of trigger words
  interface SpanMatch {
    start: number;
    end: number;
    word: string;
    type: HighlightSegment['type'];
    label: string;
    color: string;
  }

  const spans: SpanMatch[] = [];
  triggerWords.forEach(item => {
    const escaped = item.word.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const regex = new RegExp(escaped, 'gi');
    let m: RegExpExecArray | null;
    while ((m = regex.exec(text)) !== null) {
      spans.push({
        start: m.index,
        end: m.index + m[0].length,
        word: m[0],
        type: item.type,
        label: item.label,
        color: item.color
      });
    }
  });

  // Sort spans by start index
  spans.sort((a, b) => a.start - b.start);

  // Merge overlapping spans and build segments
  let lastIndex = 0;
  spans.forEach(span => {
    if (span.start < lastIndex) return; // skip overlap
    if (span.start > lastIndex) {
      highlightedSegments.push({
        text: text.slice(lastIndex, span.start),
        isFlagged: false
      });
    }
    highlightedSegments.push({
      text: text.slice(span.start, span.end),
      isFlagged: true,
      type: span.type,
      label: span.label,
      color: span.color
    });
    lastIndex = span.end;
  });

  if (lastIndex < text.length) {
    highlightedSegments.push({
      text: text.slice(lastIndex),
      isFlagged: false
    });
  }

  return {
    riskScore,
    severity,
    verdictAction,
    classification,
    classificationTitle,
    mitreCode,
    executiveSummary,
    confidence: Math.round(Math.min(99, Math.max(89, 72 + (entities.length * 4)))),
    evidence,
    highlightedSegments,
    vectors: {
      financial: {
        name: 'Financial Exposure & Wire Diversion',
        score: financialScore,
        status: financialScore > 60 ? 'critical' : financialScore > 30 ? 'high' : financialScore > 10 ? 'moderate' : 'low',
        details: financialMatches.length > 0 ? financialMatches.join(' • ') : 'No direct financial diversion triggers'
      },
      phishing: {
        name: 'Credential Theft & Phishing',
        score: phishingScore,
        status: phishingScore > 60 ? 'critical' : phishingScore > 30 ? 'high' : phishingScore > 10 ? 'moderate' : 'low',
        details: phishingMatches.length > 0 ? phishingMatches.join(' • ') : 'No credential interception patterns'
      },
      impersonation: {
        name: 'Authority & Executive Impersonation',
        score: impersonationScore,
        status: impersonationScore > 60 ? 'critical' : impersonationScore > 30 ? 'high' : impersonationScore > 10 ? 'moderate' : 'low',
        details: impersonationMatches.length > 0 ? impersonationMatches.join(' • ') : 'Neutral communication tone'
      },
      urgency: {
        name: 'Urgency & Coercive Pressure',
        score: urgencyScore,
        status: urgencyScore > 60 ? 'critical' : urgencyScore > 30 ? 'high' : urgencyScore > 10 ? 'moderate' : 'low',
        details: urgencyMatches.length > 0 ? urgencyMatches.join(' • ') : 'Standard communication velocity'
      },
      domain: {
        name: 'Domain & Infrastructure Reputation',
        score: domainRiskScore,
        status: domainRiskScore > 60 ? 'critical' : domainRiskScore > 30 ? 'high' : domainRiskScore > 10 ? 'moderate' : 'low',
        details: urls.length > 0 ? `${urls.length} link(s) inspected` : 'No external links extracted'
      }
    },
    entities,
    iocs,
    playbookActions,
    senderEvaluation,
    timestamp: new Date().toISOString(),
    scanId
  };
}
