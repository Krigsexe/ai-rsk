// VULNERABLE: LLM API call without any audit logging
const response = await openai.chat.completions.create({
  model: 'gpt-4',
  messages: conversation,
  max_tokens: 1000,
});

// Response used directly — no logging of model, tokens, user context
return response.choices[0].message.content;
