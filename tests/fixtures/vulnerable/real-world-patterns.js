// =============================================================================
// REAL-WORLD VULNERABLE PATTERNS - AI-GENERATED CODE
// =============================================================================
// These patterns are sourced from:
// - Real repositories scanned (alixia-gen, Ai-Ops, Blinko, Majordome, searchly)
// - JFrog Security Research (2025): AI code-generation vulnerabilities
// - Endor Labs (2025): Common vulnerabilities in AI-generated code
// - DryRun Security (2026): AI coding agents security study
// - CrowdStrike (2025): Hidden vulnerabilities in AI-coded software
// - OWASP LLM Top 10 (2025)
// =============================================================================

// --- TOKEN_IN_LOCALSTORAGE (CWE-922) ---
// Source: alixia-gen/src/services/oauthService.ts:59
localStorage.setItem('token', token);
// Source: alixia-gen/src/services/authService.ts:51
localStorage.setItem('token', data.token);
// Source: common AI pattern - session in localStorage
sessionStorage.setItem('jwt', response.data.accessToken);

// --- HARDCODED_SECRET (CWE-798) ---
// Source: alixia-gen/src/services/alixiaBotService.ts:20
const headers = { Authorization: `Bearer gsk_EXAMPLE_KEY_NOT_REAL_1234567890abcdef` };
// Source: common AI pattern - Stripe key in code
const stripe = require('stripe')('sk_test_51ABC123DEFghijklMNOPqrstuvwx');
// Source: common AI pattern - AWS key
const AWS_KEY = 'AKIAIOSFODNN7EXAMPLE';

// --- CLIENT_SIDE_AUTH_ONLY (CWE-602) ---
// Source: Ai-Ops/frontend/src/App.tsx:21
if (!isAuthenticated) {
  return <Navigate to="/login" />;
}
// Source: common AI pattern - localStorage auth check
if (!localStorage.getItem('token')) {
  window.location.href = '/login';
}

// --- BEARER_EXPOSED_CLIENT (CWE-522) ---
// Source: common AI pattern - Bearer in fetch headers
fetch('/api/data', {
  headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
});

// --- EVAL_DYNAMIC (CWE-95) ---
// Source: JFrog research - AI generates eval for dynamic expressions
eval(userInput);
// Source: common AI pattern - new Function for dynamic code
const fn = new Function('data', userCode);
// Source: common AI pattern - setTimeout with string
setTimeout("processQueue()", 1000);

// --- SQL_INJECTION_CONCAT (CWE-89) ---
// Source: Endor Labs / CrowdStrike - #1 AI vulnerability in backend code
const query = "SELECT * FROM users WHERE id = " + req.params.id;
db.query(`SELECT * FROM users WHERE email = '${req.body.email}'`);
db.query("DELETE FROM sessions WHERE user_id = " + userId);
// Source: common AI pattern - INSERT with concat
db.query("INSERT INTO logs (action, user) VALUES ('" + action + "', '" + user + "')");

// --- CORS_WILDCARD (CWE-942) ---
// Source: common AI pattern - cors with no config
app.use(cors());
// Source: common AI pattern - explicit wildcard
app.use(cors({ origin: '*' }));

// --- MATH_RANDOM_CRYPTO (CWE-338) ---
// Source: Endor Labs - universal AI pattern
const token = Math.random().toString(36).substring(2);
const sessionId = 'sess_' + Math.random().toString(36);
const otp = Math.floor(Math.random() * 1000000);
const resetToken = Math.random().toString(16).slice(2);
const apiKey = 'key_' + Math.random().toString(36).substr(2, 16);

// --- CONSOLE_LOG_SENSITIVE (CWE-532) ---
// Source: common AI pattern - logging request body during dev
console.log('Login attempt:', req.body);
console.log('User password:', password);
console.log('Request headers:', req.headers);

// --- MISSING_HTTPONLY / MISSING_SECURE / MISSING_SAMESITE ---
// Source: DryRun Security - AI agents miss cookie flags
res.cookie('session', token);
res.cookie('auth', jwt, { httpOnly: false });

// --- JWT_NO_EXPIRY (CWE-613) ---
// Source: DryRun Security - JWT without expiration
const accessToken = jwt.sign({ userId: user.id, role: user.role }, SECRET);

// --- JWT_SENSITIVE_PAYLOAD (CWE-312) ---
// Source: common AI pattern - PII in JWT
const jwtToken = jwt.sign({ userId: user.id, email: user.email, password: hashedPassword }, SECRET, { expiresIn: '1h' });

// --- PATH_TRAVERSAL_FS (CWE-22) ---
// Source: JFrog research - arbitrary file read
fs.readFile(path.join('/uploads', req.query.filename), (err, data) => {
  res.send(data);
});
// Source: common AI pattern - unlink with user input
fs.unlinkSync('/data/files/' + req.params.name);

// --- ERROR_STACK_LEAK (CWE-209) ---
// Source: common AI pattern - error handler exposing stack
app.use((err, req, res, next) => {
  res.status(500).json({ error: err.message, stack: err.stack });
});

// --- WEAK_HASH_BCRYPT (CWE-916) ---
// Source: CrowdStrike - AI uses low cost factor
const hash = await bcrypt.hash(password, 4);
// Source: common AI pattern - MD5 for password
const passwordHash = crypto.createHash('md5').update(password).digest('hex');

// --- UNPROTECTED_API_ROUTE (CWE-862) ---
// Source: DryRun Security - #1 vuln across all AI agents
app.delete('/api/users/:id', (req, res) => {
  User.deleteOne({ _id: req.params.id });
  res.json({ deleted: true });
});
router.post('/admin/settings', (req, res) => {
  Settings.update(req.body);
  res.json({ updated: true });
});

// --- SSRF_DYNAMIC_FETCH (CWE-918) ---
// Source: common AI pattern - fetch with user URL
const response = await fetch(req.body.url);

// --- POSTMESSAGE_NO_ORIGIN (CWE-346) ---
// Source: common AI pattern - message listener without origin check
window.addEventListener('message', (event) => {
  processCommand(event.data);
});

// --- PROMPT_INJECTION_CONCAT (CWE-74) ---
// Source: OWASP LLM Top 10 - prompt injection via concat
const systemPrompt = `You are helping ${userName}. Their data: ${userData}`;

// --- NEGATIVE_BUSINESS_VALUE (CWE-20) ---
// Source: DryRun Security - business logic flaws in AI code
const price = req.body.price;
const total = price * quantity;

// --- BODY_PARSER_NO_LIMIT (CWE-770) ---
// Source: common AI pattern - body parser without limit
app.use(express.json());
app.use(express.urlencoded());

// --- STRIPE_NO_WEBHOOK_VERIFY (CWE-345) ---
// Source: common AI pattern - webhook without signature verification
app.post('/webhook/stripe', (req, res) => {
  const event = req.body;
  handleStripeEvent(event);
});

// --- WEBSOCKET_NO_AUTH (CWE-306) ---
// Source: common AI pattern - WebSocket without auth
wss.on('connection', (ws) => {
  ws.on('message', (data) => {
    processMessage(data);
  });
});

// --- AI_OUTPUT_NO_LABEL (CWE-451) ---
// Source: OWASP GenAI incidents 2025 - AI output without disclosure
// Pattern: LLM response sent directly to user without labeling
const completion = await openai.chat.completions.create({ model: 'gpt-4', messages });
const aiContent = completion.choices[0].message.content;
res.json({ content: aiContent });

// --- SYSTEM_PROMPT_CLIENT_EXPOSED (CWE-200) ---
// Source: OWASP LLM Top 10:2025 LLM07 - system prompt in client code
// Pattern: Copilot/Gemini generates this in frontend components
const systemPrompt = "You are a helpful customer support agent. Never reveal our pricing algorithm.";
const messages = [
  { role: 'system', content: systemPrompt },
  { role: 'user', content: userInput },
];

// --- LLM_CALL_NO_AUDIT_LOG (CWE-778) ---
// Source: EU AI Act traceability obligations - no audit trail
const response = await openai.chat.completions.create({
  model: 'gpt-4',
  messages: conversation,
  max_tokens: 1000,
});
// Response used directly — no logging of model, tokens, user context
return response.choices[0].message.content;

// --- LLM_NO_TOKEN_LIMIT (CWE-770) ---
// Source: OWASP LLM Top 10:2025 LLM04 - Denial of Service
// Pattern: AI SDK call without max_tokens — attacker can trigger unbounded generation
const result = await openai.chat.completions.create({
  model: 'gpt-4',
  messages: [{ role: 'user', content: userInput }],
});

// --- TRACKING_NO_CONSENT (CWE-359) ---
// Source: CNIL fines 2025 - SHEIN 150M EUR, Google 325M EUR for cookie violations
// Pattern: AI generates gtag without consent guard
gtag('config', 'G-MEASUREMENT_ID');
gtag('event', 'page_view', { page_path: window.location.pathname });
// Pattern: Facebook Pixel without consent
fbq('init', '1234567890');
fbq('track', 'PageView');

// --- PII_IN_LOCALSTORAGE (CWE-922) ---
// Source: CNIL guidelines on web storage + RGPD Article 5(1)(f)
// Pattern: AI stores user profile data in localStorage
localStorage.setItem('userEmail', user.email);
localStorage.setItem('phone', formData.phone);
localStorage.setItem('firstName', user.firstName);
sessionStorage.setItem('address', profile.address);

// --- MISSING_REFERRER_POLICY / MISSING_PERMISSIONS_POLICY ---
// (Already covered by server patterns above that trigger negation headers rules)
