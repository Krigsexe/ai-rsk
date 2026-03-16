// VULNERABLE: AI-generated content sent to user without labeling
const response = await openai.chat.completions.create({
  model: 'gpt-4',
  messages: [{ role: 'user', content: userMessage }],
});

// Sending AI output directly to user without disclosure
const aiContent = response.choices[0].message.content;
res.json({ content: aiContent });
