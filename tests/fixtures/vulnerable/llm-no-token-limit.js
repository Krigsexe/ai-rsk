// VULNERABLE: LLM API call without max_tokens — unlimited output
const response = await openai.chat.completions.create({
  model: 'gpt-4',
  messages: [{ role: 'user', content: userInput }],
  // No max_tokens set — attacker can trigger unbounded generation
});
