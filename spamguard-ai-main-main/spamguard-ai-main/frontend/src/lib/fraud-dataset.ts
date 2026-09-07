export interface FraudDatasetItem {
  text: string;
  label: number; // 1 = Fraud / Malicious Threat, 0 = Legitimate / Benign
}

export const FRAUD_DATASET: FraudDatasetItem[] = [
  // 1. Business Email Compromise (BEC) & Executive Wire Diversion (Fraud - 1)
  { text: "URGENT & STRICTLY CONFIDENTIAL: I am in a closed-door acquisition meeting. Wire $48,500 via SWIFT to our new beneficiary account before 3:00 PM today. Do not discuss this with anyone in the office. Reply with routing confirmation immediately.", label: 1 },
  { text: "From CEO: Please process an emergency wire transfer of $75,000 to vendor account 9821-491-002 today. I am currently boarding a flight and cannot take calls. Send confirmation once processed.", label: 1 },
  { text: "Executive Notice: We are closing a private acquisition. Require immediate electronic wire transfer of $120,000 to legal escrow. Maintain strict confidentiality.", label: 1 },
  { text: "Urgent payment instruction from Managing Director: Change beneficiary account details for upcoming contractor remittance to Bank of America routing 026009593.", label: 1 },
  { text: "Confidential directive: Please settle outstanding advisory fee of $32,400 via wire transfer immediately to prevent contract termination.", label: 1 },

  // 2. Financial Impersonation & Banking Phishing (Fraud - 1)
  { text: "CHASE FRAUD ALERT: An unauthorized charge of $1,849.00 at Walmart Online has been flagged on your debit card. If you did NOT authorize this transaction, click here immediately: https://sec-chase-update.top/auth to verify your account, social security number, and card PIN.", label: 1 },
  { text: "Wells Fargo Security: A temporary hold has been placed on your account due to suspicious sign-in from Russia. Verify your identity now at https://wellsfargo-verify-security.xyz or account will be permanently locked.", label: 1 },
  { text: "Bank of America Alert: Suspicious debit transaction of $2,310.00 detected. Call 1-800-FRAUD immediately or login to cancel wire hold: https://bofa-fraud-resolution.top", label: 1 },
  { text: "Citi Alert: Your credit card has been suspended due to 3 failed attempts. Enter your 16-digit card number, CVV, and billing ZIP to restore active privileges: http://citibank-card-update.site", label: 1 },
  { text: "PayPal Fraud Department: Unauthorized payment of $650.00 to CryptoExchange Inc. To dispute this charge and request an immediate refund, click https://paypal-dispute-center.xyz", label: 1 },

  // 3. Credential Harvesting & Account Takeover (Fraud - 1)
  { text: "FINAL WARNING: Your Microsoft 365 organization password expires in 60 minutes. Click here to re-authenticate and keep your password: https://login-microsoft365-session.xyz/reauth. Failure to verify will result in permanent mailbox suspension.", label: 1 },
  { text: "Google Workspace Admin: Unusual sign-in attempt detected from unfamiliar IP 185.220.101.5. Provide your two-factor authentication OTP code immediately to secure access.", label: 1 },
  { text: "IT Helpdesk: Mandatory security patch installation required. Click link to enter corporate username and network password: http://corporate-it-support-portal.top", label: 1 },
  { text: "Okta Verification: Your session has expired. Re-enter your employee ID and master password to access corporate intranet: https://sso-okta-auth-verify.xyz", label: 1 },
  { text: "DocuSign Security: Financial statement envelope requires immediate digital signature. Log in with your email password to decrypt document: https://docusign-secure-envelope.site", label: 1 },

  // 4. Cryptocurrency & Investment Scams (Fraud - 1)
  { text: "GUARANTEED 350% WEEKLY RETURN: Automated arbitrage trading pool is now open for 20 VIP investors! Deposit 0.25 BTC or USDT to wallet 0x71C8364437a9C277799719922269756F5b574426 immediately. Guaranteed payout within 48 hours.", label: 1 },
  { text: "Exclusive Bitcoin Doubler: Send between 0.1 BTC and 5 BTC to bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh and receive 2x back instantly. Zero risk guaranteed algorithm.", label: 1 },
  { text: "Telegram Crypto Signals VIP: Make $5,000 daily with our insider pump group. Deposit $250 registration fee via Bitcoin wallet address to unlock premium channel.", label: 1 },
  { text: "Ethereum smart contract vulnerability reward: Claim your 5.5 ETH airdrop by connecting your private wallet phrase at https://eth-foundation-airdrop.xyz", label: 1 },

  // 5. Invoice Mutation & Payment Redirection (Fraud - 1)
  { text: "NOTICE OF BANKING DETAIL UPDATE: Please be advised that effective immediately, our banking details for wire transfer payments have been updated due to an annual financial audit. Please remit pending invoice #INV-9930 ($24,750.00) to our new beneficiary account.", label: 1 },
  { text: "Urgent vendor notice: Due to system migration at our bank, all remittances should now be wired to Citibank Account #984210499, Routing #021000089. Disregard previous invoices.", label: 1 },
  { text: "Invoice Overdue Notice: Immediate settlement of $18,900 required before close of business. Remit via telegraphic transfer SWIFT code CHASUS33 to prevent legal collection action.", label: 1 },

  // 6. Extortion & Coercive Pressure (Fraud - 1)
  { text: "Internal Revenue Service (IRS): A federal legal warrant has been issued in your name for unpaid tax liabilities of $4,850. Pay immediately with prepaid Target or Apple gift cards to avoid arrest.", label: 1 },
  { text: "Federal Court Subpoena: You are summoned for jury fraud trial. Immediate bail payment of $2,000 required via Western Union wire to cancel bench warrant.", label: 1 },
  { text: "Geek Squad Renewal Fraud: Your auto-debit of $499.00 has been processed for Norton 360 renewal. Call toll-free 1-888-592-0199 within 24 hours to cancel and claim refund.", label: 1 },

  // 7. Legitimate Corporate & Business Communications (Authentic - 0)
  { text: "Hi Finance Team, please find attached our monthly cloud infrastructure invoice #INV-8821 for August. The net total is $3,450.00 with standard Net-30 terms as per our master service agreement. Let us know if you need any additional PO details. Best regards, Apex Cloud Billing.", label: 0 },
  { text: "Good morning team, our sprint retrospective is scheduled for 10:30 AM in Conference Room B. Please review the sprint board beforehand.", label: 0 },
  { text: "Hi David, thanks for sending over the revised proposal. We will review it with the engineering leads on Thursday and get back to you with comments.", label: 0 },
  { text: "Quarterly all-hands meeting will take place this Friday at 3:00 PM EST. The Zoom link is in the calendar invitation.", label: 0 },
  { text: "Hi Sarah, can you please share the Q3 headcount projection spreadsheet when you have a moment? No rush, before end of week is fine.", label: 0 },
  { text: "FedEx Delivery Update: Your package with tracking #784920194821 is scheduled for delivery today between 2:00 PM and 5:00 PM. No signature required.", label: 0 },
  { text: "Thanks for your order! Your purchase of 2 office monitors has shipped. Expected delivery is Wednesday. Tracking details enclosed.", label: 0 },
  { text: "Hi Team, the staging environment deployment has completed successfully. QA can now commence regression testing.", label: 0 },
  { text: "Please review the updated employee handbook for 2026. Standard annual policy acknowledgment is available in the HR portal.", label: 0 },
  { text: "Meeting notes from today's client sync: Agreed on milestones for phase 2. Delivery timeline confirmed for late November.", label: 0 },
  { text: "Hi Alex, hope you had a good weekend. Let's catch up on the design tokens today after lunch if your calendar permits.", label: 0 },
  { text: "Your monthly utility bill for August is ready for viewing online. Total amount due is $142.50 by September 25th.", label: 0 },
  { text: "Flight confirmation for your upcoming trip to Chicago. Confirmation code: KL89X2. Check-in opens 24 hours prior to departure.", label: 0 },
  { text: "Hi everyone, the coffee machine on floor 4 has been serviced and is operational again. Thanks for your patience.", label: 0 }
];
