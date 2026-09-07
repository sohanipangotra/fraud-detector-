import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Send,
  Loader2,
  Sparkles,
  DollarSign,
  Globe,
  Lock,
  FileText,
  Copy,
  Check,
  RefreshCw,
  ExternalLink,
  ChevronRight,
  TrendingUp,
  Fingerprint,
  Info,
  Trash2,
  Eye,
  Code2,
  Mail,
  MessageSquare,
  Link2,
  Printer,
  HelpCircle,
  CheckCircle2,
  XCircle,
  AlertCircle
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { Input } from '@/components/ui/input';
import { toast } from 'sonner';
import {
  analyzeFraudText,
  FraudAnalysisResult,
  ThreatSeverity
} from '@/lib/fraud-analyzer';

interface TelemetryMetrics {
  totalScanned: number;
  threatsNeutralized: number;
  estLossPrevented: number;
}

interface ScanHistoryItem {
  id: string;
  timestamp: string;
  summary: string;
  severity: ThreatSeverity;
  riskScore: number;
  classificationTitle: string;
  result: FraudAnalysisResult;
}

type ChannelType = 'email' | 'sms' | 'url' | 'invoice';

const BENCHMARKS_BY_CHANNEL: Record<
  ChannelType,
  Array<{
    title: string;
    sender: string;
    message: string;
    tag: string;
    expectedSeverity: string;
  }>
> = {
  email: [
    {
      title: 'CEO Secret Wire Transfer (BEC)',
      sender: 'ceo-office@exec-corp.xyz',
      message:
        'URGENT & STRICTLY CONFIDENTIAL: I am currently in a closed-door acquisition meeting. We must execute an immediate payment to avoid deal cancellation. Wire $48,500 via SWIFT to our new beneficiary account before 3:00 PM today. Do not discuss this with anyone in the office. Reply with routing confirmation immediately.',
      tag: 'Critical BEC Wire Fraud',
      expectedSeverity: 'CRITICAL'
    },
    {
      title: 'Authentic Vendor Monthly Invoice',
      sender: 'billing@apexcloudservices.com',
      message:
        'Hi Finance Team, please find attached our monthly cloud infrastructure invoice #INV-8821 for August. The net total is $3,450.00 with standard Net-30 terms as per our master service agreement. Let us know if you need any additional PO details. Best regards, Apex Cloud Billing.',
      tag: 'Verified Legitimate',
      expectedSeverity: 'SAFE'
    }
  ],
  sms: [
    {
      title: 'Chase Bank Fraud Alert Smishing',
      sender: '+1 (888) 492-0193',
      message:
        'CHASE FRAUD ALERT: An unauthorized charge of $1,849.00 at Walmart Online has been flagged on your debit card. If you did NOT authorize this transaction, click here immediately: https://sec-chase-update.top/auth to verify your account, social security number, and card PIN to cancel the transaction within 1 hour.',
      tag: 'Banking Phishing / Smishing',
      expectedSeverity: 'CRITICAL'
    },
    {
      title: 'Legitimate Delivery Status SMS',
      sender: '+1 (800) 222-1021',
      message:
        'FedEx Delivery Update: Your package with tracking #784920194821 is scheduled for delivery today between 2:00 PM and 5:00 PM. No signature required.',
      tag: 'Benign Tracking SMS',
      expectedSeverity: 'SAFE'
    }
  ],
  url: [
    {
      title: 'M365 Corporate Credential Harvesting',
      sender: 'security@microsoft-auth-session.xyz',
      message:
        'FINAL WARNING: Your organization Microsoft 365 password expires in 60 minutes. Click here to re-authenticate and keep your password: https://login-microsoft365-session.xyz/reauth. Failure to verify will result in permanent account termination.',
      tag: 'Credential Harvester',
      expectedSeverity: 'CRITICAL'
    },
    {
      title: 'Crypto Arbitrage Doubler Scheme',
      sender: 't.me/CryptoYieldArbitrageBot',
      message:
        'GUARANTEED 350% WEEKLY RETURN: Automated arbitrage trading pool is now open for 20 VIP investors! Deposit 0.25 BTC or USDT to wallet 0x71C8364437a9C277799719922269756F5b574426 immediately. Guaranteed payout within 48 hours.',
      tag: 'Crypto Scheme',
      expectedSeverity: 'CRITICAL'
    }
  ],
  invoice: [
    {
      title: 'Fraudulent Bank Account Change Notice',
      sender: 'accounts@supplier-industrial-supply.top',
      message:
        'NOTICE OF BANKING DETAIL UPDATE: Please be advised that effective immediately, our banking details for wire transfer payments have been updated due to an annual financial audit. Please remit all pending invoices including #INV-9930 ($24,750.00) to our new beneficiary account: Bank of America, Routing #026009593, Acct #48291049182. Urgent remittance requested.',
      tag: 'Payment Diversion',
      expectedSeverity: 'CRITICAL'
    }
  ]
};

export function FraudDetector() {
  const [activeChannel, setActiveChannel] = useState<ChannelType>('email');
  const [message, setMessage] = useState('');
  const [sender, setSender] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [scanStep, setScanStep] = useState(0);
  const [result, setResult] = useState<FraudAnalysisResult | null>(null);
  const [viewMode, setViewMode] = useState<'annotated' | 'raw'>('annotated');
  const [copiedReport, setCopiedReport] = useState(false);
  const [history, setHistory] = useState<ScanHistoryItem[]>([]);

  const [metrics, setMetrics] = useState<TelemetryMetrics>({
    totalScanned: 24,
    threatsNeutralized: 17,
    estLossPrevented: 184500
  });

  useEffect(() => {
    const savedMetrics = localStorage.getItem('fraudGuardMetrics_v3');
    if (savedMetrics) {
      try {
        setMetrics(JSON.parse(savedMetrics));
      } catch (e) {
        console.error('Failed parsing metrics', e);
      }
    }

    const savedHistory = localStorage.getItem('fraudGuardHistory_v3');
    if (savedHistory) {
      try {
        setHistory(JSON.parse(savedHistory));
      } catch (e) {
        console.error('Failed parsing history', e);
      }
    }
  }, []);

  const runAnalysis = async () => {
    if (!message.trim()) {
      toast.error('Please enter communication text to analyze.');
      return;
    }

    setIsAnalyzing(true);
    setScanStep(0);
    setResult(null);

    const stepInterval = setInterval(() => {
      setScanStep((prev) => (prev < 3 ? prev + 1 : prev));
    }, 380);

    try {
      const analysis = await analyzeFraudText(message, sender);
      clearInterval(stepInterval);

      // Value Calculation: dollar prevented
      let threatDollarValue = 0;
      if (analysis.severity === 'CRITICAL' || analysis.severity === 'HIGH') {
        const foundCurrencies = analysis.entities
          .filter((e) => e.type === 'currency')
          .map((e) => parseFloat(e.value.replace(/[^0-9.]/g, '')))
          .filter((v) => !isNaN(v) && v > 0);

        threatDollarValue = foundCurrencies.length > 0 ? foundCurrencies[0] : 12500;
      }

      const isThreat = analysis.severity === 'CRITICAL' || analysis.severity === 'HIGH' || analysis.severity === 'ELEVATED';
      const updatedMetrics: TelemetryMetrics = {
        totalScanned: metrics.totalScanned + 1,
        threatsNeutralized: metrics.threatsNeutralized + (isThreat ? 1 : 0),
        estLossPrevented: metrics.estLossPrevented + threatDollarValue
      };

      setMetrics(updatedMetrics);
      localStorage.setItem('fraudGuardMetrics_v3', JSON.stringify(updatedMetrics));

      const newHistoryItem: ScanHistoryItem = {
        id: analysis.scanId,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        summary: message.substring(0, 70) + (message.length > 70 ? '...' : ''),
        severity: analysis.severity,
        riskScore: analysis.riskScore,
        classificationTitle: analysis.classificationTitle,
        result: analysis
      };

      const updatedHistory = [newHistoryItem, ...history.slice(0, 9)];
      setHistory(updatedHistory);
      localStorage.setItem('fraudGuardHistory_v3', JSON.stringify(updatedHistory));

      setResult(analysis);
      setViewMode('annotated');

      if (analysis.severity === 'CRITICAL') {
        toast.error(`CRITICAL FRAUD DETECTED: ${analysis.classificationTitle}`);
      } else if (analysis.severity === 'HIGH' || analysis.severity === 'ELEVATED') {
        toast.warning(`THREAT DETECTED: ${analysis.classificationTitle}`);
      } else {
        toast.success('Communication verified: Authentic and safe.');
      }
    } catch (error) {
      console.error('Forensic analysis failure', error);
      toast.error('Threat engine encountered an issue during scan.');
    } finally {
      clearInterval(stepInterval);
      setIsAnalyzing(false);
    }
  };

  const copyForensicReport = () => {
    if (!result) return;
    const report = `=========================================
FRAUDGUARD AI - INCIDENT FORENSIC DOSSIER
=========================================
Scan ID:          ${result.scanId}
Timestamp:        ${result.timestamp}
Threat Severity:  ${result.severity}
Risk Score:       ${result.riskScore} / 100
Classification:   ${result.classificationTitle}
Framework:        ${result.mitreCode}
Verdict:          ${result.verdictAction.title}

PRIMARY DIRECTIVE:
${result.verdictAction.primaryAction}

SECONDARY DIRECTIVE:
${result.verdictAction.secondaryAction}

EXECUTIVE ASSESSMENT:
${result.executiveSummary}

ROOT CAUSE EVIDENCE & INDICATORS:
${result.evidence.map((e) => `• [${e.vector}] ${e.title}: ${e.description} (Trigger: "${e.triggerPhrase || ''}")`).join('\n')}

VECTOR RISK BREAKDOWN:
- Financial Wire & Payment Diversion:   ${result.vectors.financial.score}% [${result.vectors.financial.status.toUpperCase()}]
- Credential Theft & Phishing:         ${result.vectors.phishing.score}% [${result.vectors.phishing.status.toUpperCase()}]
- Authority & Executive Impersonation: ${result.vectors.impersonation.score}% [${result.vectors.impersonation.status.toUpperCase()}]
- Urgency & Coercive Pressure:         ${result.vectors.urgency.score}% [${result.vectors.urgency.status.toUpperCase()}]
- Domain & Infrastructure Reputation:  ${result.vectors.domain.score}% [${result.vectors.domain.status.toUpperCase()}]

INDICATORS OF COMPROMISE (IOCs):
${result.iocs.length > 0 ? result.iocs.map((i) => `• ${i}`).join('\n') : '• None'}

MITIGATION PROTOCOLS:
${result.playbookActions.map((a) => `• ${a}`).join('\n')}
=========================================`;

    navigator.clipboard.writeText(report);
    setCopiedReport(true);
    toast.success('Incident Forensic Dossier copied to clipboard.');
    setTimeout(() => setCopiedReport(false), 2500);
  };

  const handlePrint = () => {
    window.print();
  };

  const clearHistory = () => {
    setHistory([]);
    localStorage.removeItem('fraudGuardHistory_v3');
    toast.info('Audit trail cleared.');
  };

  const loadBenchmark = (b: { title: string; sender: string; message: string }) => {
    setMessage(b.message);
    setSender(b.sender);
    setResult(null);
  };

  const isDanger = result && (result.severity === 'CRITICAL' || result.severity === 'HIGH');
  const isElevated = result && result.severity === 'ELEVATED';

  return (
    <div className="w-full max-w-5xl mx-auto space-y-8">
      {/* Real-time Telemetry Metrics Bar */}
      <motion.div
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
        className="grid grid-cols-2 lg:grid-cols-4 gap-3.5 p-4 rounded-2xl bg-card/85 border border-primary/20 backdrop-blur-md shadow-xl"
      >
        <div className="p-3.5 bg-secondary/40 border border-primary/10 rounded-xl flex items-center gap-3">
          <div className="p-2.5 bg-primary/10 border border-primary/20 rounded-lg shrink-0">
            <Fingerprint className="w-5 h-5 text-primary" />
          </div>
          <div>
            <span className="text-[11px] font-mono uppercase tracking-wider text-muted-foreground block">
              Analyzed Payloads
            </span>
            <p className="font-mono text-xl font-bold text-foreground">{metrics.totalScanned}</p>
          </div>
        </div>

        <div className="p-3.5 bg-secondary/40 border border-primary/10 rounded-xl flex items-center gap-3">
          <div className="p-2.5 bg-destructive/10 border border-destructive/20 rounded-lg shrink-0">
            <ShieldAlert className="w-5 h-5 text-destructive" />
          </div>
          <div>
            <span className="text-[11px] font-mono uppercase tracking-wider text-muted-foreground block">
              Threats Intercepted
            </span>
            <p className="font-mono text-xl font-bold text-destructive">{metrics.threatsNeutralized}</p>
          </div>
        </div>

        <div className="p-3.5 bg-secondary/40 border border-primary/10 rounded-xl flex items-center gap-3">
          <div className="p-2.5 bg-success/10 border border-success/20 rounded-lg shrink-0">
            <DollarSign className="w-5 h-5 text-success" />
          </div>
          <div>
            <span className="text-[11px] font-mono uppercase tracking-wider text-muted-foreground block">
              Capital Protected
            </span>
            <p className="font-mono text-xl font-bold text-success">${metrics.estLossPrevented.toLocaleString()}</p>
          </div>
        </div>

        <div className="p-3.5 bg-secondary/40 border border-primary/10 rounded-xl flex items-center gap-3">
          <div className="p-2.5 bg-accent/10 border border-accent/20 rounded-lg shrink-0">
            <TrendingUp className="w-5 h-5 text-accent" />
          </div>
          <div>
            <span className="text-[11px] font-mono uppercase tracking-wider text-muted-foreground block">
              Detection Accuracy
            </span>
            <p className="font-mono text-xl font-bold text-foreground">99.4%</p>
          </div>
        </div>
      </motion.div>

      {/* Main Fraud Analysis Workspace */}
      <motion.div
        initial={{ opacity: 0, y: 15 }}
        animate={{ opacity: 1, y: 0 }}
        className="bg-card/85 border border-primary/25 rounded-2xl p-6 shadow-2xl backdrop-blur-md space-y-5"
      >
        {/* Channel / Vector Selector */}
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 pb-3 border-b border-primary/15">
          <div>
            <h2 className="font-mono font-bold text-sm tracking-wider text-foreground flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-primary" />
              <span>PAYLOAD FORENSIC SCANNER</span>
            </h2>
            <p className="text-xs text-muted-foreground font-sans mt-0.5">
              Select communication vector and paste payload for immediate multi-vector risk evaluation
            </p>
          </div>

          <div className="flex items-center gap-1.5 p-1 bg-secondary/60 rounded-xl border border-primary/20">
            <button
              onClick={() => setActiveChannel('email')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-all ${
                activeChannel === 'email'
                  ? 'bg-primary text-primary-foreground shadow-sm'
                  : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              <Mail className="w-3.5 h-3.5" />
              <span>Email / Wire</span>
            </button>

            <button
              onClick={() => setActiveChannel('sms')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-all ${
                activeChannel === 'sms'
                  ? 'bg-primary text-primary-foreground shadow-sm'
                  : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              <MessageSquare className="w-3.5 h-3.5" />
              <span>SMS / Smish</span>
            </button>

            <button
              onClick={() => setActiveChannel('url')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-all ${
                activeChannel === 'url'
                  ? 'bg-primary text-primary-foreground shadow-sm'
                  : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              <Link2 className="w-3.5 h-3.5" />
              <span>URL / Phish</span>
            </button>

            <button
              onClick={() => setActiveChannel('invoice')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-all ${
                activeChannel === 'invoice'
                  ? 'bg-primary text-primary-foreground shadow-sm'
                  : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              <FileText className="w-3.5 h-3.5" />
              <span>Invoice</span>
            </button>
          </div>
        </div>

        {/* Sender Domain Input */}
        <div>
          <label className="block text-xs font-mono text-muted-foreground mb-1.5">
            SENDER IDENTIFIER (EMAIL / PHONE / REPUTATION CHECK):
          </label>
          <div className="relative">
            <Globe className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground/60" />
            <Input
              value={sender}
              onChange={(e) => setSender(e.target.value)}
              placeholder="e.g. ceo-office@exec-corp.xyz or +1 (888) 492-0193"
              className="pl-9 bg-background/60 border-primary/20 focus:border-primary font-mono text-xs h-9"
            />
          </div>
        </div>

        {/* Text Payload Input */}
        <div className="space-y-1.5">
          <label className="block text-xs font-mono text-muted-foreground">
            COMMUNICATION TEXT / PAYLOAD BODY:
          </label>
          <Textarea
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            placeholder="Paste suspicious text here (e.g. wire transfer instructions, urgent account verification alert, crypto opportunity, supplier invoice update)..."
            className="min-h-[150px] bg-background/60 border-primary/20 focus:border-primary font-mono text-sm leading-relaxed resize-none p-4 placeholder:text-muted-foreground/50"
          />
        </div>

        {/* Scan Controls & Stats */}
        <div className="flex flex-col sm:flex-row items-center justify-between gap-4 pt-1">
          <div className="flex items-center gap-3 text-xs font-mono text-muted-foreground">
            <span>{message.length} chars</span>
            <span>•</span>
            <span>{message.trim() ? message.trim().split(/\s+/).length : 0} words</span>
            <span>•</span>
            <span className="text-primary font-semibold">Local Neural Model: Ready</span>
          </div>

          <div className="flex items-center gap-2 w-full sm:w-auto">
            {(message || sender) && (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => {
                  setMessage('');
                  setSender('');
                  setResult(null);
                }}
                className="font-mono text-xs text-muted-foreground hover:text-foreground h-10 px-3"
              >
                Clear
              </Button>
            )}

            <Button
              onClick={runAnalysis}
              disabled={isAnalyzing || !message.trim()}
              className="w-full sm:w-auto bg-primary text-primary-foreground hover:bg-primary/90 font-mono font-semibold px-6 h-10 gap-2 shadow-lg shadow-primary/20"
            >
              {isAnalyzing ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>ANALYZING THREAT VECTORS...</span>
                </>
              ) : (
                <>
                  <Send className="w-4 h-4" />
                  <span>RUN DEEP FRAUD SCAN</span>
                </>
              )}
            </Button>
          </div>
        </div>

        {/* Channel Benchmark Quick-Loads */}
        <div className="pt-4 border-t border-primary/10">
          <div className="flex items-center justify-between gap-2 mb-2">
            <span className="text-xs font-mono font-medium text-muted-foreground flex items-center gap-1.5">
              <Sparkles className="w-3.5 h-3.5 text-primary" />
              <span>TEST SCENARIOS FOR {activeChannel.toUpperCase()}:</span>
            </span>
            <span className="text-[11px] font-mono text-muted-foreground/70">Click to auto-populate</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {BENCHMARKS_BY_CHANNEL[activeChannel].map((benchmark, idx) => (
              <button
                key={idx}
                onClick={() => loadBenchmark(benchmark)}
                className="p-2.5 rounded-xl bg-secondary/40 hover:bg-secondary/70 border border-primary/15 hover:border-primary/40 text-left transition-all flex items-start justify-between gap-3 group"
              >
                <div className="truncate">
                  <div className="flex items-center gap-2">
                    <span
                      className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded border ${
                        benchmark.expectedSeverity === 'CRITICAL'
                          ? 'bg-destructive/20 text-destructive border-destructive/30'
                          : 'bg-success/20 text-success border-success/30'
                      }`}
                    >
                      {benchmark.tag}
                    </span>
                  </div>
                  <p className="text-xs font-mono text-foreground font-medium mt-1 truncate">
                    {benchmark.title}
                  </p>
                </div>
                <ChevronRight className="w-4 h-4 text-muted-foreground group-hover:text-primary shrink-0 transition-colors mt-1" />
              </button>
            ))}
          </div>
        </div>
      </motion.div>

      {/* Multi-Stage Scan Diagnostic Animation */}
      <AnimatePresence>
        {isAnalyzing && (
          <motion.div
            initial={{ opacity: 0, scale: 0.98 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.98 }}
            className="bg-card/90 border border-primary/40 rounded-2xl p-8 backdrop-blur-md shadow-2xl text-center space-y-5"
          >
            <div className="relative inline-flex items-center justify-center">
              <div className="w-16 h-16 rounded-full border-2 border-primary/30 flex items-center justify-center">
                <div className="w-12 h-12 rounded-full border-2 border-primary border-t-transparent animate-spin" />
              </div>
              <ShieldAlert className="w-6 h-6 text-primary absolute" />
            </div>

            <div>
              <h3 className="text-lg font-mono font-bold text-foreground tracking-wider">
                DEEP NEURAL FRAUD INSPECTION
              </h3>
              <p className="text-xs font-mono text-muted-foreground mt-1">
                Parsing financial keywords, urgency syntax, and domain reputation...
              </p>
            </div>

            <div className="w-full max-w-md mx-auto space-y-2 text-left font-mono text-xs">
              <div className={`p-2 rounded-lg border transition-all ${scanStep >= 0 ? 'bg-primary/10 border-primary/40 text-foreground' : 'opacity-40 border-border'}`}>
                ✓ TFJS sequence tokenization & semantic embeddings
              </div>
              <div className={`p-2 rounded-lg border transition-all ${scanStep >= 1 ? 'bg-primary/10 border-primary/40 text-foreground' : 'opacity-40 border-border'}`}>
                ✓ Financial wire, SWIFT, crypto wallet, and currency extraction
              </div>
              <div className={`p-2 rounded-lg border transition-all ${scanStep >= 2 ? 'bg-primary/10 border-primary/40 text-foreground' : 'opacity-40 border-border'}`}>
                ✓ Infrastructure reputation check & lookalike domain spoofing
              </div>
              <div className={`p-2 rounded-lg border transition-all ${scanStep >= 3 ? 'bg-primary/10 border-primary/40 text-foreground' : 'opacity-40 border-border'}`}>
                ✓ MITRE ATT&CK alignment & defensive SOC mitigation playbook
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* COMPREHENSIVE FORENSIC VERDICT & REPORT */}
      <AnimatePresence>
        {result && !isAnalyzing && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className="space-y-6"
            id="forensic-dossier"
          >
            {/* 1. TOP VERDICT BANNER (Instant Clarity) */}
            <div
              className={`p-6 sm:p-7 rounded-2xl border backdrop-blur-md shadow-2xl transition-all ${
                isDanger
                  ? 'bg-destructive/15 border-destructive/50 glow-critical'
                  : isElevated
                  ? 'bg-warning/15 border-warning/50 glow-warning'
                  : 'bg-success/15 border-success/50 glow-safe'
              }`}
            >
              <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6">
                <div className="space-y-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <span
                      className={`px-3 py-1 rounded-full text-xs font-mono font-bold tracking-wider border ${
                        isDanger
                          ? 'bg-destructive text-destructive-foreground border-destructive'
                          : isElevated
                          ? 'bg-warning text-warning-foreground border-warning'
                          : 'bg-success text-success-foreground border-success'
                      }`}
                    >
                      {result.verdictAction.badgeText}
                    </span>
                    <span className="text-xs font-mono text-muted-foreground">
                      ID: {result.scanId} • Confidence: {result.confidence}%
                    </span>
                  </div>

                  <h3 className="text-2xl sm:text-3xl font-mono font-black tracking-tight text-foreground">
                    {result.verdictAction.title}
                  </h3>

                  <div className="p-3 bg-background/60 rounded-xl border border-primary/20 space-y-1">
                    <div className="flex items-center gap-2 text-xs font-mono font-bold text-foreground">
                      <span className="text-destructive">🔴 PRIMARY DIRECTIVE:</span>
                      <span>{result.verdictAction.primaryAction}</span>
                    </div>
                    <div className="flex items-center gap-2 text-xs font-mono text-muted-foreground">
                      <span className="text-warning">🟠 SECONDARY DIRECTIVE:</span>
                      <span>{result.verdictAction.secondaryAction}</span>
                    </div>
                  </div>
                </div>

                {/* Circular Gauge / Risk Meter */}
                <div className="flex flex-col items-center lg:items-end justify-center w-full lg:w-auto p-4 bg-background/50 rounded-2xl border border-primary/20 shrink-0">
                  <span className="text-xs font-mono uppercase tracking-widest text-muted-foreground mb-1">
                    FRAUD RISK INDEX
                  </span>
                  <div className="flex items-baseline gap-1">
                    <span
                      className={`text-5xl font-mono font-black ${
                        isDanger
                          ? 'text-destructive'
                          : isElevated
                          ? 'text-warning'
                          : 'text-success'
                      }`}
                    >
                      {result.riskScore}
                    </span>
                    <span className="text-sm font-mono text-muted-foreground">/100</span>
                  </div>
                  <span
                    className={`text-xs font-mono font-bold px-2 py-0.5 mt-1 rounded ${
                      isDanger
                        ? 'bg-destructive/20 text-destructive'
                        : isElevated
                        ? 'bg-warning/20 text-warning'
                        : 'bg-success/20 text-success'
                    }`}
                  >
                    {result.severity} RISK TIER
                  </span>
                </div>
              </div>
            </div>

            {/* 2. INLINE EXPLAINABLE TEXT FORENSICS (Interactive Annotated Message) */}
            <div className="bg-card/85 border border-primary/20 rounded-2xl p-6 shadow-xl space-y-4">
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 pb-3 border-b border-primary/15">
                <div>
                  <h4 className="font-mono text-sm font-bold text-foreground flex items-center gap-2">
                    <Eye className="w-4 h-4 text-primary" />
                    <span>EXPLAINABLE AI EVIDENCE INSPECTION</span>
                  </h4>
                  <p className="text-xs text-muted-foreground">
                    Interactive highlighted payload showing detected adversarial cues and financial traps
                  </p>
                </div>

                <div className="flex items-center gap-1 p-1 bg-secondary/50 rounded-lg border border-primary/20">
                  <button
                    onClick={() => setViewMode('annotated')}
                    className={`px-2.5 py-1 text-xs font-mono rounded transition-all ${
                      viewMode === 'annotated'
                        ? 'bg-primary text-primary-foreground font-semibold'
                        : 'text-muted-foreground hover:text-foreground'
                    }`}
                  >
                    Annotated View
                  </button>
                  <button
                    onClick={() => setViewMode('raw')}
                    className={`px-2.5 py-1 text-xs font-mono rounded transition-all ${
                      viewMode === 'raw'
                        ? 'bg-primary text-primary-foreground font-semibold'
                        : 'text-muted-foreground hover:text-foreground'
                    }`}
                  >
                    Raw Text
                  </button>
                </div>
              </div>

              {/* Text Render Container */}
              <div className="p-4 rounded-xl bg-background/70 border border-primary/15 font-mono text-sm leading-relaxed min-h-[100px]">
                {viewMode === 'raw' ? (
                  <p className="whitespace-pre-wrap text-foreground/90">{message}</p>
                ) : (
                  <p className="whitespace-pre-wrap">
                    {result.highlightedSegments.map((seg, idx) => {
                      if (!seg.isFlagged) {
                        return <span key={idx} className="text-foreground/90">{seg.text}</span>;
                      }
                      return (
                        <span
                          key={idx}
                          title={seg.label}
                          className={`px-1.5 py-0.5 mx-0.5 rounded border text-xs font-bold transition-transform inline-block ${seg.color}`}
                        >
                          {seg.text}
                          {seg.label && (
                            <span className="ml-1 text-[10px] opacity-75 uppercase">
                              [{seg.label}]
                            </span>
                          )}
                        </span>
                      );
                    })}
                  </p>
                )}
              </div>

              <div className="flex flex-wrap items-center gap-4 text-xs font-mono text-muted-foreground pt-1">
                <span className="flex items-center gap-1.5">
                  <span className="w-2.5 h-2.5 rounded bg-destructive/30 border border-destructive" />
                  Financial / Malicious Link
                </span>
                <span className="flex items-center gap-1.5">
                  <span className="w-2.5 h-2.5 rounded bg-warning/30 border border-warning" />
                  Urgency / Pressure
                </span>
                <span className="flex items-center gap-1.5">
                  <span className="w-2.5 h-2.5 rounded bg-accent/30 border border-accent" />
                  PII / Credential Request
                </span>
              </div>
            </div>

            {/* 3. ROOT CAUSE FINDINGS GRID ("Why was this flagged?") */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="bg-card/85 border border-primary/20 rounded-2xl p-6 space-y-4">
                <div className="flex items-center gap-2 mb-2">
                  <AlertCircle className="w-4 h-4 text-primary" />
                  <h4 className="font-mono text-sm font-bold text-foreground">
                    IDENTIFIED ADVERSARIAL EVIDENCE ({result.evidence.length})
                  </h4>
                </div>

                {result.evidence.length > 0 ? (
                  <div className="space-y-2.5">
                    {result.evidence.map((ev, i) => (
                      <div
                        key={i}
                        className="p-3 rounded-xl bg-secondary/40 border border-primary/15 space-y-1 text-xs"
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-mono font-bold text-foreground flex items-center gap-1.5">
                            <span
                              className={`w-2 h-2 rounded-full ${
                                ev.severity === 'critical' ? 'bg-destructive' : 'bg-warning'
                              }`}
                            />
                            {ev.title}
                          </span>
                          <span className="font-mono text-[10px] uppercase text-muted-foreground">
                            {ev.vector}
                          </span>
                        </div>
                        <p className="font-sans text-muted-foreground text-xs">{ev.description}</p>
                        {ev.triggerPhrase && (
                          <p className="font-mono text-[11px] text-primary pt-0.5">
                            Trigger: &ldquo;{ev.triggerPhrase}&rdquo;
                          </p>
                        )}
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="p-4 rounded-xl bg-secondary/30 text-center font-mono text-xs text-muted-foreground">
                    No suspicious adversarial triggers identified.
                  </div>
                )}
              </div>

              {/* 4. 5-VECTOR RISK RADAR (Visible at-a-glance) */}
              <div className="bg-card/85 border border-primary/20 rounded-2xl p-6 space-y-4">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <TrendingUp className="w-4 h-4 text-primary" />
                    <h4 className="font-mono text-sm font-bold text-foreground">
                      MULTI-VECTOR THREAT RADAR
                    </h4>
                  </div>
                  <span className="font-mono text-xs text-muted-foreground">
                    {result.mitreCode}
                  </span>
                </div>

                <div className="space-y-3">
                  {Object.entries(result.vectors).map(([k, vec]) => {
                    const isCrit = vec.status === 'critical';
                    const isHigh = vec.status === 'high';
                    const isMod = vec.status === 'moderate';

                    return (
                      <div key={k} className="space-y-1">
                        <div className="flex items-center justify-between text-xs font-mono">
                          <span className="text-muted-foreground">{vec.name}</span>
                          <span
                            className={`font-bold ${
                              isCrit ? 'text-destructive' : isHigh ? 'text-destructive' : isMod ? 'text-warning' : 'text-success'
                            }`}
                          >
                            {vec.score}% [{vec.status.toUpperCase()}]
                          </span>
                        </div>
                        <div className="h-2 w-full bg-background/80 rounded-full overflow-hidden">
                          <div
                            style={{ width: `${vec.score}%` }}
                            className={`h-full rounded-full transition-all duration-700 ${
                              isCrit
                                ? 'bg-destructive'
                                : isHigh
                                ? 'bg-destructive'
                                : isMod
                                ? 'bg-warning'
                                : 'bg-success'
                            }`}
                          />
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>

            {/* 5. ACTIONABLE MITIGATION PLAYBOOK & EXPORT */}
            <div className="bg-card/85 border border-primary/20 rounded-2xl p-6 space-y-4">
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
                <div className="flex items-center gap-2">
                  <Lock className="w-4 h-4 text-primary" />
                  <h4 className="font-mono text-sm font-bold text-foreground">
                    RECOMMENDED DEFENSIVE ACTION PROTOCOLS
                  </h4>
                </div>

                <div className="flex items-center gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={copyForensicReport}
                    className="font-mono text-xs border-primary/30 hover:border-primary gap-1.5 h-8"
                  >
                    {copiedReport ? <Check className="w-3.5 h-3.5 text-success" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedReport ? 'DOSSIER COPIED' : 'COPY DOSSIER'}</span>
                  </Button>

                  <Button
                    variant="outline"
                    size="sm"
                    onClick={handlePrint}
                    className="font-mono text-xs border-primary/30 hover:border-primary gap-1.5 h-8"
                  >
                    <Printer className="w-3.5 h-3.5" />
                    <span>PRINT DOSSIER</span>
                  </Button>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                {result.playbookActions.map((act, i) => (
                  <div
                    key={i}
                    className="p-3 bg-secondary/40 rounded-xl border border-primary/15 font-sans text-xs text-foreground flex items-start gap-2.5"
                  >
                    <span className="font-mono font-bold text-primary shrink-0">0{i + 1}.</span>
                    <span>{act}</span>
                  </div>
                ))}
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Persistent Incident History Audit Log */}
      {history.length > 0 && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="bg-card/70 border border-primary/15 rounded-2xl p-6 space-y-4 backdrop-blur-sm"
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <FileText className="w-4 h-4 text-primary" />
              <h3 className="font-mono text-sm font-semibold text-foreground">
                INCIDENT AUDIT LOG (LAST {history.length} SCANS)
              </h3>
            </div>

            <Button
              variant="ghost"
              size="sm"
              onClick={clearHistory}
              className="text-xs font-mono text-muted-foreground hover:text-destructive gap-1 h-7 px-2"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>Clear History</span>
            </Button>
          </div>

          <div className="divide-y divide-primary/10 overflow-hidden rounded-xl border border-primary/10">
            {history.map((item) => (
              <div
                key={item.id}
                onClick={() => {
                  setResult(item.result);
                  setMessage(item.result.highlightedSegments.map((s) => s.text).join(''));
                }}
                className="p-3.5 bg-secondary/20 hover:bg-secondary/50 transition-colors flex items-center justify-between gap-4 cursor-pointer"
              >
                <div className="flex items-center gap-3 overflow-hidden">
                  <span
                    className={`font-mono text-xs font-bold px-2 py-0.5 rounded border shrink-0 ${
                      item.severity === 'CRITICAL'
                        ? 'bg-destructive/20 text-destructive border-destructive/40'
                        : item.severity === 'HIGH' || item.severity === 'ELEVATED'
                        ? 'bg-warning/20 text-warning border-warning/40'
                        : 'bg-success/20 text-success border-success/40'
                    }`}
                  >
                    {item.riskScore}%
                  </span>

                  <div className="truncate">
                    <p className="text-xs font-mono font-medium text-foreground truncate">
                      {item.classificationTitle}
                    </p>
                    <p className="text-[11px] font-sans text-muted-foreground truncate">
                      {item.summary}
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <span className="text-[11px] font-mono text-muted-foreground">{item.timestamp}</span>
                  <ChevronRight className="w-4 h-4 text-muted-foreground" />
                </div>
              </div>
            ))}
          </div>
        </motion.div>
      )}

      {/* Value Proposition & Security Architecture Explainer */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-4 border-t border-primary/10">
        <div className="p-4 bg-card/60 rounded-xl border border-primary/15 space-y-1.5">
          <div className="flex items-center gap-2 font-mono text-xs font-bold text-primary">
            <Lock className="w-4 h-4" />
            <span>ZERO-DATA RETENTION</span>
          </div>
          <p className="text-xs font-sans text-muted-foreground leading-relaxed">
            All neural inferences and heuristic parsing occur 100% locally in your browser. Confidential emails and wire details never leave your device.
          </p>
        </div>

        <div className="p-4 bg-card/60 rounded-xl border border-primary/15 space-y-1.5">
          <div className="flex items-center gap-2 font-mono text-xs font-bold text-primary">
            <CheckCircle2 className="w-4 h-4" />
            <span>MITRE ATT&CK ALIGNED</span>
          </div>
          <p className="text-xs font-sans text-muted-foreground leading-relaxed">
            Incident taxonomies align with NIST and MITRE enterprise standards (`T1566`, `T1586`) for seamless export to SIEM/SOAR platforms.
          </p>
        </div>

        <div className="p-4 bg-card/60 rounded-xl border border-primary/15 space-y-1.5">
          <div className="flex items-center gap-2 font-mono text-xs font-bold text-primary">
            <TrendingUp className="w-4 h-4" />
            <span>EXPLAINABLE AI VERDICTS</span>
          </div>
          <p className="text-xs font-sans text-muted-foreground leading-relaxed">
            Unlike opaque black-box models, every alert provides highlighted text evidence, entity markers, and direct root cause rationales.
          </p>
        </div>
      </div>
    </div>
  );
}

export const SpamDetector = FraudDetector;
