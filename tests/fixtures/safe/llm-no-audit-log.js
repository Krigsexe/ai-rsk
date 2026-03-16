// SAFE: LLM API call with audit logging via Helicone
const { OpenAI } = require('openai');
const openai = new OpenAI({
  baseURL: 'https://oai.helicone.ai/v1',
});

const response = await openai.chat.completions.create({
  model: 'gpt-4',
  messages: conversation,
  max_tokens: 1000,
});

// Helicone automatically logs: timestamp, model, tokens, latency
auditLog({
  timestamp: new Date().toISOString(),
  model: response.model,
  tokens: response.usage.total_tokens,
});
