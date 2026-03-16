// SAFE: Only non-PII data in browser storage

// Theme preference — not PII
localStorage.setItem('theme', 'dark');
localStorage.getItem('theme');

// Language preference — not PII
localStorage.setItem('lang', 'fr');
localStorage.setItem('locale', 'en-US');

// Session token handling: use httpOnly cookies server-side, not browser storage

// UI state — not PII
sessionStorage.setItem('sidebar_collapsed', 'true');
sessionStorage.setItem('last_tab', 'settings');

// Redirect URL — not PII
localStorage.setItem('redirect_after_login', '/dashboard');

// Cart items — not PII
localStorage.setItem('cart', JSON.stringify(items));

// Feature flags — not PII
localStorage.setItem('feature_dark_mode', 'enabled');
