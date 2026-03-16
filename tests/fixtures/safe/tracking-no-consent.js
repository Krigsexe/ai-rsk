// SAFE: All tracking scripts gated behind consent mechanisms

// Google Consent Mode v2 — defaults set to denied
gtag('consent', 'default', {
  analytics_storage: 'denied',
  ad_storage: 'denied',
});

// Only load after user grants cookieConsent
function initAnalytics() {
  if (cookieConsent.analytics) {
    gtag('consent', 'update', { analytics_storage: 'granted' });
    gtag('config', 'G-XXXXXXXXXX');
  }
}

// Facebook Pixel with consent gate
fbq('consent', 'revoke');
function onCookieConsentGranted() {
  fbq('consent', 'grant');
  fbq('init', '1234567890');
  fbq('track', 'PageView');
}

// Matomo with consent check
if (hasConsent('analytics')) {
  _paq.push(['trackPageView']);
}

// CookieBot integration
window.addEventListener('CookiebotOnAccept', function() {
  if (Cookiebot.consent.statistics) {
    gtag('config', 'G-XXXXXXXXXX');
  }
});

// OneTrust integration
function OptanonWrapper() {
  if (OnetrustActiveGroups.includes('C0002')) {
    gtag('event', 'page_view');
  }
}

// tarteaucitron integration
tarteaucitron.user.gtagUa = 'G-XXXXXXXXXX';
(tarteaucitron.job = tarteaucitron.job || []).push('gtag');
