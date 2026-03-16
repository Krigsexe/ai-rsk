// VULNERABLE: Tracking scripts loaded without any consent mechanism
// Violates RGPD Article 6 + ePrivacy Directive Article 5(3)

// Google Analytics — direct initialization without consent check
gtag('config', 'G-XXXXXXXXXX');

// Google Analytics — event tracking without consent
gtag('event', 'page_view', {
  page_title: 'Home',
  page_path: '/',
});

// Facebook Pixel — initialization without consent
fbq('init', '1234567890');
fbq('track', 'PageView');

// Matomo — tracking without consent
_paq.push(['trackPageView']);
_paq.push(['enableLinkTracking']);

// Real-world pattern from ai-alixia: gtag event without consent guard
function handleLanguageChange(langCode) {
  if (window.gtag && oldLang !== langCode) {
    window.gtag('event', 'language_change', {
      event_category: 'Settings',
      from_language: oldLang,
      to_language: langCode,
    });
  }
}
