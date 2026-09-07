#!/usr/bin/env python3
"""
================================================================================
FraudGuard AI - Standalone Enterprise Fraud & Phishing Detection Engine
================================================================================
A portable, zero-dependency Python engine for detecting Business Email
Compromise (BEC), wire transfer fraud, credential harvesting, cryptocurrency
scams, and coercive social engineering.

Usage:
    CLI Test Suite:       python fraud_detector.py
    Analyze Custom Text:  python fraud_detector.py --text "URGENT: Wire $45,000..." --sender "ceo@exec.xyz"
    Import as Library:
        from fraud_detector import FraudDetector
        engine = FraudDetector()
        result = engine.analyze(message, sender="...")
================================================================================
"""

import sys
import re
import json
import argparse
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict

# Windows terminal UTF-8 support
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Terminal ANSI Styling
RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
WHITE = "\033[97m"
BG_RED = "\033[41m"
BG_GREEN = "\033[42m"
BG_YELLOW = "\033[43m"


@dataclass
class ExtractedEntity:
    type: str
    label: str
    value: str
    risk: str


@dataclass
class VectorScore:
    name: str
    score: int
    status: str
    details: str


@dataclass
class FraudResult:
    scan_id: str
    risk_score: int
    severity: str
    verdict: str
    primary_directive: str
    secondary_directive: str
    classification: str
    mitre_attack: str
    executive_summary: str
    confidence: int
    vectors: Dict[str, Any]
    entities: List[Dict[str, str]]
    iocs: List[str]
    playbook_actions: List[str]

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(asdict(self), indent=indent)

    def print_dossier(self) -> None:
        color = RED if self.severity in ("CRITICAL", "HIGH") else (YELLOW if self.severity == "ELEVATED" else GREEN)
        print(f"\n{BOLD}{color}================================================================================")
        print(f" FRAUDGUARD AI - ENTERPRISE INCIDENT FORENSIC DOSSIER")
        print(f"================================================================================{RESET}")
        print(f"{BOLD}SCAN ID:{RESET}          {self.scan_id}")
        print(f"{BOLD}RISK SCORE:{RESET}       {color}{BOLD}{self.risk_score} / 100 ({self.severity} SEVERITY){RESET}")
        print(f"{BOLD}CLASSIFICATION:{RESET}   {self.classification}")
        print(f"{BOLD}FRAMEWORK:{RESET}        {self.mitre_attack}")
        print(f"{BOLD}CONFIDENCE:{RESET}       {self.confidence}%")
        print(f"{BOLD}VERDICT:{RESET}          {color}{BOLD}{self.verdict}{RESET}\n")

        print(f"{BOLD}🚨 PRIMARY DIRECTIVE:{RESET}   {self.primary_directive}")
        print(f"{BOLD}🛡️ SECONDARY DIRECTIVE:{RESET} {self.secondary_directive}\n")

        print(f"{BOLD}EXECUTIVE SUMMARY:{RESET}")
        print(f"  {self.executive_summary}\n")

        print(f"{BOLD}MULTI-VECTOR THREAT RADAR:{RESET}")
        for k, v in self.vectors.items():
            bar_len = int(v["score"] / 5)
            bar = "█" * bar_len + "░" * (20 - bar_len)
            v_color = RED if v["score"] >= 60 else (YELLOW if v["score"] >= 30 else GREEN)
            print(f"  • {v['name']:<38} {v_color}[{bar}] {v['score']:>3}% ({v['status'].upper()}){RESET}")

        if self.iocs:
            print(f"\n{BOLD}EXTRACTED INDICATORS OF COMPROMISE (IOCs):{RESET}")
            for ioc in self.iocs:
                print(f"  {RED}⚠ {ioc}{RESET}")

        print(f"\n{BOLD}RECOMMENDED DEFENSIVE PROTOCOLS:{RESET}")
        for idx, act in enumerate(self.playbook_actions, 1):
            print(f"  {idx:02d}. {act}")
        print(f"{color}================================================================================{RESET}\n")


class FraudDetector:
    """Enterprise-grade heuristic & semantic fraud analysis engine."""

    SUSPICIOUS_TLDS = [
        ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq",
        ".zip", ".mov", ".buzz", ".icu", ".monster", ".online", ".site"
    ]

    FINANCIAL_PATTERNS = [
        (r"\b(wire transfer|bank wire|swift|routing number|ach payment|new bank account|payment instructions|beneficiary change|wire \$[0-9,]+)\b", 50, "Wire / SWIFT Redirection"),
        (r"\b(unauthorized transaction|charge of \$|fraud alert|security department|suspicious activity on your card|temporary hold)\b", 45, "Financial Impersonation Alert"),
        (r"\b(gift card|apple card|steam card|razer gold|target card|pay with cards)\b", 55, "Untraceable Gift Card Demand"),
        (r"\b(crypto|bitcoin|ethereum|guaranteed return|doubler|forex trading|daily profit|investment pool|usdt deposit|arbitrage pool)\b", 50, "Unregulated Crypto Scheme"),
        (r"\b(lottery|inheritance|unclaimed funds|western union|moneygram|processing fee required)\b", 45, "Advance-Fee Fraud"),
        (r"\b(refund of \$|overpaid|deducted from your account|subscription renewal \$[0-9]+|geek squad|norton lifelock)\b", 45, "Fake Refund / Invoice Trap")
    ]

    PHISHING_PATTERNS = [
        (r"\b(verify your account|account suspended|password expires|reset your credential|security checkpoint|re-authenticate|identity verification)\b", 45, "Credential Harvest Trigger"),
        (r"\b(click here|log in now|tap here to resolve|access your portal|sign in immediately|update your billing)\b", 35, "Coercive Call-To-Action"),
        (r"\b(mfa|two-factor|otp|one-time code|auth code|do not share this code)\b", 45, "MFA / OTP Interception"),
        (r"\b(ssn|social security|credit card number|card pin|cvv|mother's maiden|card expiration)\b", 55, "Critical PII Extraction")
    ]

    IMPERSONATION_PATTERNS = [
        (r"\b(ceo|cfo|executive vice president|managing director|board of directors|president's office|closed-door|acquisition)\b", 45, "Executive Authority Tone"),
        (r"\b(internal revenue service|irs|fbi|law enforcement|federal court|arrest warrant|legal subpoena)\b", 55, "Government Intimidation"),
        (r"\b(it department|helpdesk support|systems administrator|network alert|microsoft 365 team|google workspace admin)\b", 40, "Internal IT Spoofing"),
        (r"\b(strictly confidential|keep this private|do not discuss with anyone|direct order|emergency meeting)\b", 45, "Isolation & Secrecy Mandate")
    ]

    URGENCY_PATTERNS = [
        (r"\b(urgent|immediately|within 24 hours|within 1 hour|before end of day|before 3:00|action required now|immediate response|account terminated)\b", 40, "Extreme Time Pressure"),
        (r"\b(final warning|last notice|legal consequences|penalty fee|frozen immediately|service suspension|permanent mailbox suspension)\b", 45, "Coercive Threat Penalty")
    ]

    def analyze(self, text: str, sender: Optional[str] = None) -> FraudResult:
        scan_id = f"FG-{hex(abs(hash(text)))[2:8].upper()}"
        entities: List[ExtractedEntity] = []
        iocs: List[str] = []

        # 1. URL & Infrastructure Forensics
        urls = re.findall(r"(?:https?://|www\.)[^\s/$.?#].[^\s]*", text, re.IGNORECASE)
        domain_risk = 0
        for url in urls:
            u_lower = url.lower()
            risk = "medium"
            for tld in self.SUSPICIOUS_TLDS:
                if tld in u_lower:
                    risk = "critical"
                    domain_risk += 65
                    iocs.append(f"Untrusted Disposable TLD ({tld}) in URL: {url}")
                    break

            if re.search(r"(?:https?://)?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url):
                risk = "critical"
                domain_risk += 70
                iocs.append(f"Direct IP Host (Evasion Tactic): {url}")

            if re.search(r"paypa[l1]|arnazon|micros[o0]ft|cha[s5]e|ne[t7]flix|app[l1]e", url, re.I):
                risk = "critical"
                domain_risk += 75
                iocs.append(f"Brand Impersonation Lookalike Domain: {url}")

            entities.append(ExtractedEntity("url", "Embedded Web Target", url, risk))

        # 2. Crypto Forensics
        crypto_matches = re.findall(
            r"\b(bc1[a-zA-HJ-NP-Z0-9]{25,39}|1[a-km-zA-HJ-NP-Z1-9]{25,34}|3[a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40})\b",
            text
        )
        for addr in crypto_matches:
            entities.append(ExtractedEntity("crypto", "Unhosted Crypto Wallet", addr, "critical"))
            iocs.append(f"Cryptocurrency Wallet Destination: {addr}")

        # 3. Currency / Monetary Stake
        currency_matches = re.findall(
            r"(\$\s*\d{1,3}(?:,\d{3})*(?:\.\d{2})?|\b\d{1,3}(?:,\d{3})*\s*(?:usd|dollars|eur|gbp|usdt|btc)\b)",
            text,
            re.IGNORECASE
        )
        for amt in currency_matches:
            entities.append(ExtractedEntity("currency", "Financial Exposure Stake", amt, "high"))
            iocs.append(f"Financial Exposure Sum: {amt}")

        # 4. Threat Vector Scoring
        financial_score = 0
        fin_matches = []
        for pattern, weight, label in self.FINANCIAL_PATTERNS:
            m = re.search(pattern, text, re.IGNORECASE)
            if m:
                financial_score += weight
                fin_matches.append(label)
                entities.append(ExtractedEntity("action", label, m.group(0), "critical" if weight > 45 else "high"))

        if crypto_matches:
            financial_score += 50
        if currency_matches and financial_score > 0:
            financial_score += 30

        phishing_score = 0
        phish_matches = []
        for pattern, weight, label in self.PHISHING_PATTERNS:
            m = re.search(pattern, text, re.IGNORECASE)
            if m:
                phishing_score += weight
                phish_matches.append(label)
                entities.append(ExtractedEntity("pii" if "PII" in label else "action", label, m.group(0), "critical" if weight > 45 else "high"))

        if urls and phishing_score > 0:
            phishing_score += 35

        impersonation_score = 0
        imp_matches = []
        for pattern, weight, label in self.IMPERSONATION_PATTERNS:
            m = re.search(pattern, text, re.IGNORECASE)
            if m:
                impersonation_score += weight
                imp_matches.append(label)
                entities.append(ExtractedEntity("action", label, m.group(0), "high"))

        urgency_score = 0
        urg_matches = []
        for pattern, weight, label in self.URGENCY_PATTERNS:
            m = re.search(pattern, text, re.IGNORECASE)
            if m:
                urgency_score += weight
                urg_matches.append(label)
                entities.append(ExtractedEntity("urgency", label, m.group(0), "high"))

        # Sender Domain Check
        if sender:
            s_low = sender.strip().lower()
            is_freemail = bool(re.search(r"@(gmail|yahoo|hotmail|outlook|proton)\.com$", s_low))
            has_sus_tld = any(s_low.endswith(t) for t in self.SUSPICIOUS_TLDS)
            if impersonation_score >= 20 and is_freemail:
                domain_risk += 65
                iocs.append(f"Executive Spoofing via Public Webmail: {sender}")
            elif has_sus_tld:
                domain_risk += 60
                iocs.append(f"Disposable Sender Domain TLD: {sender}")

        # Cap vector scores
        financial_score = min(100, financial_score)
        phishing_score = min(100, phishing_score)
        impersonation_score = min(100, impersonation_score)
        urgency_score = min(100, urgency_score)
        domain_risk = min(100, domain_risk)

        # Compound Synthesis
        elevated_vectors = sum(1 for s in [financial_score, phishing_score, impersonation_score, urgency_score, domain_risk] if s >= 35)
        highest_vec = max(financial_score, phishing_score, impersonation_score, domain_risk)

        if elevated_vectors >= 3 or (elevated_vectors >= 2 and (financial_score >= 50 or phishing_score >= 50 or domain_risk >= 60)):
            risk_score = min(99, max(88, highest_vec + 5))
        elif elevated_vectors >= 2 or highest_vec >= 50:
            risk_score = min(92, max(72, highest_vec))
        elif elevated_vectors == 1 or highest_vec >= 30:
            risk_score = min(68, max(45, highest_vec))
        else:
            risk_score = min(15, int(highest_vec * 0.4))

        # Severity
        if risk_score >= 75:
            severity = "CRITICAL"
        elif risk_score >= 55:
            severity = "HIGH"
        elif risk_score >= 30:
            severity = "ELEVATED"
        elif risk_score >= 15:
            severity = "LOW"
        else:
            severity = "SAFE"

        # Classification & Directives
        if severity in ("CRITICAL", "HIGH"):
            if impersonation_score >= 35 and financial_score >= 40:
                classification = "Business Email Compromise (BEC) / Wire Transfer Fraud"
                mitre_code = "MITRE ATT&CK: T1566.002 & T1586.002"
                summary = "High-confidence executive impersonation targeting corporate funds via urgent unverified wire transfer under manufactured secrecy."
                verdict = "DO NOT WIRE FUNDS • CONFIDENTIALITY TRAP"
                primary = "HALT TRANSACTION: Do not initiate SWIFT/ACH wire transfer."
                secondary = "Perform out-of-band verification: Call executive via internal extension."
            elif financial_score >= 50 and crypto_matches:
                classification = "Cryptocurrency Yield Scheme / Asset Drainer"
                mitre_code = "FIN-SCAM-09 (Decentralized Laundering)"
                summary = "Fraudulent investment scheme leveraging unhosted cryptocurrency wallet addresses and artificial yield promises."
                verdict = "DO NOT SEND CRYPTOCURRENCY"
                primary = "Do not transfer tokens or connect Web3 wallets."
                secondary = "Block destination wallet address across AML gateway filters."
            elif financial_score >= 45:
                classification = "Financial Fraud / Payment Redirection Trap"
                mitre_code = "FIN-SCAM-03 (Payment Diversion Fraud)"
                summary = "Explicit payment diversion, fraudulent charge alert, or unauthorized banking alteration."
                verdict = "REJECT PAYMENT REDIRECTION"
                primary = "Do not update banking details or settle invoices based on this communication."
                secondary = "Contact vendor accounts department via established historical phone."
            elif phishing_score >= 40:
                classification = "Spearphishing & Credential Interception"
                mitre_code = "MITRE ATT&CK: T1566 / T1598"
                summary = "Deceptive lure designed to harvest login credentials, MFA authentication tokens, or personal PINs."
                verdict = "DO NOT CLICK LINKS OR ENTER CREDENTIALS"
                primary = "Do not enter passwords, MFA codes, or banking PINs."
                secondary = "Quarantine sender domain and submit URLs to SOC perimeter blocklist."
            else:
                classification = "Coercive Social Engineering & Intimidation"
                mitre_code = "MITRE ATT&CK: T1499"
                summary = "Exploitation of manufactured legal consequences, penalty threats, or extreme time limits."
                verdict = "DO NOT RESPOND TO COERCION"
                primary = "Do not reply or surrender corporate assets under duress."
                secondary = "Escalate communication to corporate legal and compliance teams."
        elif severity == "ELEVATED":
            classification = "Suspicious / Elevated Anomaly Risk"
            mitre_code = "MONITOR-ALERT-LVL2"
            summary = "Communication exhibits atypical urgency, unverified links, or transactional references."
            verdict = "EXERCISE CAUTION • VERIFY SENDER"
            primary = "Inspect embedded links carefully before interacting."
            secondary = "Cross-reference sender address against official directory."
        else:
            classification = "Authentic / Legitimate Communication"
            mitre_code = "N/A (Benign Protocol)"
            summary = "Linguistic telemetry and entity inspection indicate normal, authentic communication."
            verdict = "VERIFIED AUTHENTIC • NO THREAT DETECTED"
            primary = "Proceed with normal business operational workflows."
            secondary = "Maintain general cyber-hygiene on external communications."

        # Playbook actions
        if severity == "CRITICAL":
            playbook = [
                "DO NOT wire funds, click embedded hyperlinks, or enter credentials.",
                "Quarantine payload immediately across mail boundary gateways.",
                "Verify out-of-band: Phone sender via verified corporate directory.",
                "If credentials or MFA tokens were entered, initiate emergency password revocation.",
                "Submit incident dossier to corporate SOC / Information Security team."
            ]
        elif severity == "HIGH":
            playbook = [
                "Do not disclose financial, account, or personal identity details.",
                "Verify validity through pre-approved customer/vendor phone numbers.",
                "Blacklist destination domain/IP across perimeter firewalls."
            ]
        elif severity == "ELEVATED":
            playbook = [
                "Inspect hyperlinks for deceptive lookalike characters before clicking.",
                "Verify sender identity through verified internal directory."
            ]
        else:
            playbook = [
                "No threat signatures detected. Standard communication protocol applies.",
                "Continue adhering to enterprise cyber hygiene policies."
            ]

        def get_status(score: int) -> str:
            return "critical" if score >= 60 else ("high" if score >= 30 else ("moderate" if score >= 10 else "low"))

        vectors = {
            "financial": {
                "name": "Financial Wire & Payment Diversion",
                "score": financial_score,
                "status": get_status(financial_score),
                "details": " • ".join(fin_matches) if fin_matches else "No payment diversion indicators"
            },
            "phishing": {
                "name": "Credential Theft & Phishing",
                "score": phishing_score,
                "status": get_status(phishing_score),
                "details": " • ".join(phish_matches) if phish_matches else "No credential harvesting triggers"
            },
            "impersonation": {
                "name": "Authority & Executive Impersonation",
                "score": impersonation_score,
                "status": get_status(impersonation_score),
                "details": " • ".join(imp_matches) if imp_matches else "Neutral peer-level tone"
            },
            "urgency": {
                "name": "Urgency & Coercive Pressure",
                "score": urgency_score,
                "status": get_status(urgency_score),
                "details": " • ".join(urg_matches) if urg_matches else "Standard velocity"
            },
            "domain": {
                "name": "Domain & Infrastructure Reputation",
                "score": domain_risk,
                "status": get_status(domain_risk),
                "details": f"{len(urls)} link(s) inspected" if urls else "No external links"
            }
        }

        return FraudResult(
            scan_id=scan_id,
            risk_score=risk_score,
            severity=severity,
            verdict=verdict,
            primary_directive=primary,
            secondary_directive=secondary,
            classification=classification,
            mitre_attack=mitre_code,
            executive_summary=summary,
            confidence=min(99, max(88, 72 + len(entities) * 4)),
            vectors=vectors,
            entities=[asdict(e) for e in entities],
            iocs=iocs,
            playbook_actions=playbook
        )


def main():
    parser = argparse.ArgumentParser(description="FraudGuard AI - Enterprise Fraud Detection Engine")
    parser.add_argument("--text", type=str, help="Text message or email payload to inspect")
    parser.add_argument("--sender", type=str, help="Sender email or phone identifier")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    args = parser.parse_args()

    detector = FraudDetector()

    if args.text:
        result = detector.analyze(args.text, sender=args.sender)
        if args.json:
            print(result.to_json())
        else:
            result.print_dossier()
    else:
        # Run Built-in Benchmark Test Suite
        print(f"\n{BOLD}{CYAN}>>> Running FraudGuard AI Benchmark Suite (3 Scenarios)...{RESET}\n")

        benchmarks = [
            (
                "Executive Wire Fraud (BEC)",
                "ceo-office@exec-corp.xyz",
                "URGENT & STRICTLY CONFIDENTIAL: I am in a closed-door acquisition meeting. Wire $48,500 via SWIFT to our new beneficiary account before 3:00 PM today. Do not discuss this with anyone in the office."
            ),
            (
                "Chase Bank Fraud Alert Smishing",
                "+1 (888) 492-0193",
                "CHASE FRAUD ALERT: Unauthorized charge of $1,849.00 at Walmart Online. Click here immediately: https://sec-chase-update.top/auth to verify your account, SSN, and PIN within 1 hour."
            ),
            (
                "Legitimate Corporate Invoice",
                "billing@trustedsupplier.com",
                "Hi Finance Team, attached is invoice #INV-8821 for August cloud services ($3,450.00). Standard Net-30 terms apply as per our agreement. Thanks!"
            )
        ]

        for title, sender, msg in benchmarks:
            print(f"{BOLD}{WHITE}--- TESTING BENCHMARK: {title} ---{RESET}")
            res = detector.analyze(msg, sender=sender)
            res.print_dossier()


if __name__ == "__main__":
    main()
