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
    const { message } = await req.json();

    if (!message || typeof message !== 'string') {
      return new Response(
        JSON.stringify({ error: 'Message is required' }),
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

    const systemPrompt = `You are an expert spam detection AI. Analyze the given message and determine if it's spam or not.

You must respond with a JSON object containing:
- "isSpam": boolean (true if spam, false if not)
- "confidence": number between 0 and 100 (your confidence percentage)
- "reasoning": string (brief explanation of why you made this decision)
- "indicators": array of strings (specific spam indicators found, or reasons it's legitimate)

Spam indicators to look for:
- Urgent language ("Act now!", "Limited time!", "Don't miss out!")
- Suspicious links or requests to click
- Requests for personal/financial information
- Lottery/prize winning claims
- Get-rich-quick schemes
- Impersonation of banks, companies, or authorities
- Poor grammar/spelling (often intentional to bypass filters)
- Pressure tactics or threats
- Too-good-to-be-true offers
- Unsolicited promotional content
- Phishing attempts
- Cryptocurrency scams

Respond ONLY with the JSON object, no additional text.`;

    console.log("Analyzing message for spam:", message.substring(0, 100) + "...");

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
          { role: "user", content: `Analyze this message for spam:\n\n${message}` }
        ],
        temperature: 0.3,
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
        JSON.stringify({ error: 'Failed to analyze message' }),
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

    // Parse the JSON response from AI
    let result;
    try {
      // Clean up the response if it contains markdown code blocks
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
        JSON.stringify({ error: 'Failed to parse AI analysis' }),
        { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    // Determine status based on confidence thresholds
    let status: 'spam' | 'suspicious' | 'safe';
    if (result.isSpam && result.confidence >= 90) {
      status = 'spam';
    } else if (result.isSpam && result.confidence >= 60 || (!result.isSpam && result.confidence < 60)) {
      status = 'suspicious';
    } else {
      status = 'safe';
    }

    const finalResult = {
      isSpam: result.isSpam,
      confidence: result.confidence,
      status,
      reasoning: result.reasoning,
      indicators: result.indicators || [],
    };

    console.log("Analysis complete:", finalResult);

    return new Response(
      JSON.stringify(finalResult),
      { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );

  } catch (error) {
    console.error("Error in detect-spam function:", error);
    return new Response(
      JSON.stringify({ error: error instanceof Error ? error.message : 'Unknown error' }),
      { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
  }
});
