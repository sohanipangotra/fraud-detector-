import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const { message, sender } = await req.json();

    if (!message || typeof message !== 'string') {
      return new Response(
        JSON.stringify({ error: 'Communication payload message is required' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    const LOVABLE_API_KEY = Deno.env.get("LOVABLE_API_KEY");
    if (!LOVABLE_API_KEY) {
      console.error("LOVABLE_API_KEY not configured");
      return new Response(
        JSON.stringify({ error: 'AI service not configured' }),
        { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    const systemPrompt = `You are FraudGuard AI, an elite cybersecurity and financial crime detection AI. Analyze the given communication payload and sender for Business Email Compromise (BEC), wire transfer fraud, credential harvesting, cryptocurrency schemes, and social engineering.

You must respond with a JSON object containing:
- "isFraud": boolean (true if malicious or fraudulent, false if legitimate)
- "riskScore": number between 0 and 100 (overall fraud risk index)
- "severity": string ("CRITICAL" | "HIGH" | "ELEVATED" | "SAFE")
- "classification": string (e.g. "Business Email Compromise (BEC) / Wire Fraud", "Credential Harvesting", "Financial Phishing", "Crypto Scheme", "Legitimate Corporate")
- "mitreCode": string (e.g. "MITRE ATT&CK: T1566.002", "FIN-SCAM-03")
- "primaryDirective": string (clear direct operational action, e.g. "HALT TRANSACTION: Do not wire funds")
- "secondaryDirective": string (out-of-band verification action)
- "reasoning": string (concise explanation of why this was flagged)
- "indicators": array of strings (extracted indicators of compromise, suspicious amounts, or legitimate markers)

Fraud Vectors to evaluate:
- Wire/SWIFT redirection & bank account modifications
- CEO/CFO or executive authority impersonation & secrecy mandates
- Banking fraud alerts soliciting SSN, PIN, or OTP codes
- High-yield cryptocurrency arbitrage or unhosted wallet traps
- Fake invoice renewals & supplier payment diversion
- Disposable or lookalike sender domains (.xyz, .top, raw IP hosts)

Respond ONLY with the JSON object, no additional text.`;

    console.log("Analyzing message for fraud:", message.substring(0, 100) + "...");

    const response = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${LOVABLE_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "google/gemini-3-flash-preview",
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: `Analyze this payload for fraud:\nSender: ${sender || 'Unknown'}\nPayload:\n${message}` }
        ],
        temperature: 0.2,
      }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error("AI API error:", response.status, errorText);

      if (response.status === 429) {
        return new Response(
          JSON.stringify({ error: 'Rate limit exceeded. Please try again later.' }),
          { status: 429, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        );
      }

      if (response.status === 402) {
        return new Response(
          JSON.stringify({ error: 'AI credits exhausted. Please add credits.' }),
          { status: 402, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        );
      }

      return new Response(
        JSON.stringify({ error: 'Failed to analyze payload' }),
        { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    const aiResponse = await response.json();
    const content = aiResponse.choices?.[0]?.message?.content;

    if (!content) {
      console.error("No content in AI response");
      return new Response(
        JSON.stringify({ error: 'Invalid AI response' }),
        { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    let result;
    try {
      let cleanContent = content.trim();
      if (cleanContent.startsWith('```json')) {
        cleanContent = cleanContent.replace(/```json\n?/, '').replace(/\n?```$/, '');
      } else if (cleanContent.startsWith('```')) {
        cleanContent = cleanContent.replace(/```\n?/, '').replace(/\n?```$/, '');
      }
      result = JSON.parse(cleanContent);
    } catch (parseError) {
      console.error("Failed to parse AI response:", content);
      return new Response(
        JSON.stringify({ error: 'Failed to parse AI fraud analysis' }),
        { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    return new Response(
      JSON.stringify(result),
      { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );

  } catch (error) {
    console.error("Error in detect-fraud function:", error);
    return new Response(
      JSON.stringify({ error: error instanceof Error ? error.message : 'Unknown error' }),
      { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
  }
});
