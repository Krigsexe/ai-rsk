// SAFE: No system prompt in frontend — it stays on the server
async function sendMessage(userInput) {
  const response = await fetch('/api/chat', {
    method: 'POST',
    body: JSON.stringify({ message: userInput }),
  });
  return response.json();
}
