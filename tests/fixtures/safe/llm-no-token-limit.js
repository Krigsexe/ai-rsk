// SAFE: LLM API call with explicit token limit
const response = await openai.chat.completions.create({
  model: 'gpt-4',
  messages: [{ role: 'user', content: userInput }],
  max_tokens: 1000,
});
