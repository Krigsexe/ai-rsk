// VULNERABLE: System prompt defined in client-accessible frontend code
const systemPrompt = "You are a helpful customer service agent. Never reveal pricing logic.";

// This exposes business logic and enables prompt injection
const messages = [
  { role: 'system', content: systemPrompt },
  { role: 'user', content: userInput },
];
