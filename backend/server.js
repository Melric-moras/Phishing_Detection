const express = require('express');
const cors = require('cors');
const app = express();

app.use(cors());
app.use(express.json());
const path = require("path");

app.use(express.static(path.join(__dirname, "../frontend")));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "../frontend/index.html"));
});
// ─────────────────────────────────────────────
// DETECTION DATA
// ─────────────────────────────────────────────

const TRUSTED_DOMAINS = [
  'google.com', 'sbi.co.in', 'hdfcbank.com', 'icicibank.com',
  'axisbank.com', 'paytm.com', 'phonepe.com', 'npci.org.in',
  'gov.in', 'uidai.gov.in', 'irctc.co.in', 'amazon.in',
  'flipkart.com', 'youtube.com', 'facebook.com', 'instagram.com',
  'amazon.com', 'microsoft.com', 'apple.com', 'netflix.com',
  'whatsapp.com', 'twitter.com', 'x.com', 'linkedin.com',
  'razorpay.com', 'billdesk.com', 'rbi.org.in'
];

// Brands that get checked for impersonation in URLs
const BRAND_NAMES = [
  'paypal', 'sbi', 'hdfc', 'icici', 'axis', 'google', 'facebook',
  'amazon', 'apple', 'microsoft', 'netflix', 'paytm', 'phonepe',
  'whatsapp', 'instagram', 'twitter', 'linkedin', 'uber', 'ola',
  'zomato', 'swiggy', 'razorpay'
];

const BRAND_OFFICIAL_DOMAINS = {
  paypal:    ['paypal.com'],
  sbi:       ['sbi.co.in'],
  hdfc:      ['hdfcbank.com'],
  icici:     ['icicibank.com'],
  axis:      ['axisbank.com'],
  google:    ['google.com', 'googleapis.com', 'google.co.in'],
  facebook:  ['facebook.com', 'fb.com'],
  amazon:    ['amazon.com', 'amazon.in', 'amazonaws.com'],
  apple:     ['apple.com', 'icloud.com'],
  microsoft: ['microsoft.com', 'live.com', 'outlook.com', 'hotmail.com'],
  netflix:   ['netflix.com'],
  paytm:     ['paytm.com'],
  phonepe:   ['phonepe.com'],
  whatsapp:  ['whatsapp.com', 'whatsapp.net'],
  instagram: ['instagram.com'],
  twitter:   ['twitter.com', 'x.com'],
  linkedin:  ['linkedin.com'],
  uber:      ['uber.com'],
  ola:       ['olacabs.com'],
  zomato:    ['zomato.com'],
  swiggy:    ['swiggy.com'],
  razorpay:  ['razorpay.com'],
};

// Known typosquatting patterns for major brands
const TYPOSQUAT_PATTERNS = [
  { pattern: /paypa[l1i][-.]|paypa[l1i][^a-z0-9]/i, brand: 'PayPal' },
  { pattern: /g[o0]{2}g[l1e]e|g[o0]gle/i,           brand: 'Google'   },
  { pattern: /faceb[o0]{2}k|facebok/i,               brand: 'Facebook' },
  { pattern: /amaz0n|arnazon|anazon/i,                brand: 'Amazon'   },
  { pattern: /micros[o0]ft|mircosoft/i,              brand: 'Microsoft'},
  { pattern: /app1e|appl3|aple\./i,                  brand: 'Apple'    },
  { pattern: /inst[a4]gr[a4]m/i,                     brand: 'Instagram'},
  { pattern: /linkedln|1inkedin|linkdin/i,            brand: 'LinkedIn' },
  { pattern: /wh[a4]ts[a4]pp/i,                      brand: 'WhatsApp' },
];

// Domains used to shorten/obscure URLs
const URL_SHORTENER_RE = /^(bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly|shorturl\.|rb\.gy|cutt\.ly|tiny\.cc|s\.id|v\.gd)$/i;

// High-risk TLDs (.xyz, .ml, etc.) – free / throwaway registrations
const SUSPICIOUS_TLDS_HIGH   = ['.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw'];
// Medium-risk TLDs – not throwaway but overused in phishing
const SUSPICIOUS_TLDS_MEDIUM = ['.click', '.link', '.top', '.work', '.party', '.download', '.loan', '.win', '.bid'];

// Words that relate to credential harvesting
const CREDENTIAL_KEYWORDS = [
  'login', 'verify', 'verification', 'account', 'password', 'otp',
  'kyc', 'confirm', 'suspend', 'suspended', 'upi', 'pin', 'secure',
  'security', 'authenticate', 'validation', 'reactivate', 'update'
];

// Words that relate to luring with rewards
const LURE_KEYWORDS = [
  'free', 'offer', 'prize', 'winner', 'won', 'claim',
  'cashback', 'refund', 'limited', 'deal', 'lucky', 'reward',
  'gift', 'bonus', 'earn', 'money', 'cash'
];

// ─────────────────────────────────────────────
// URL ANALYSIS  (recalibrated scoring)
// ─────────────────────────────────────────────

function extractDomain(url) {
  try {
    if (!url.startsWith('http')) url = 'https://' + url;
    return new URL(url).hostname.replace(/^www\./, '').toLowerCase();
  } catch {
    return url.replace(/^https?:\/\//, '').split('/')[0].toLowerCase();
  }
}

function analyzeURL(url) {
  let score   = 0;
  const reasons = [];
  const domain  = extractDomain(url);
  const urlLow  = url.toLowerCase();

  // ── 1. Trusted domain — instant SAFE ──────────────────────────────────────
  const trusted = TRUSTED_DOMAINS.some(d => domain === d || domain.endsWith('.' + d));
  if (trusted) {
    return { status: 'SAFE', score: 0, reasons: ['Verified trusted website.'] };
  }

  // ── 2. Raw IP address (45 pts) ─────────────────────────────────────────────
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(domain)) {
    score += 45;
    reasons.push('Uses a raw IP address — legitimate websites always use a domain name.');
  }

  // ── 3. URL shortener (50 pts) ──────────────────────────────────────────────
  const domainNoPort = domain.split(':')[0];
  if (URL_SHORTENER_RE.test(domainNoPort)) {
    score += 50;
    reasons.push('Uses a URL shortener that hides the real destination.');
  }

  // ── 4. Typosquatting (55 pts) ──────────────────────────────────────────────
  let isTyposquat = false;
  for (const { pattern, brand } of TYPOSQUAT_PATTERNS) {
    if (pattern.test(domain)) {
      score += 55;
      isTyposquat = true;
      reasons.push(`Misspells "${brand}"'s domain name — classic typosquatting to steal credentials.`);
      break;
    }
  }

  // ── 5. Brand impersonation — only when not already caught as typosquat ─────
  let hasBrandImpersonation = false;
  if (!isTyposquat) {
    for (const brand of BRAND_NAMES) {
      if (domain.includes(brand)) {
        const officials = BRAND_OFFICIAL_DOMAINS[brand] || [];
        const isOfficial = officials.some(d => domain === d || domain.endsWith('.' + d));
        if (!isOfficial) {
          score += 20;
          hasBrandImpersonation = true;
          reasons.push(`Contains "${brand}" but is not the official ${brand} website.`);
          break;
        }
      }
    }
  }

  // ── 6. Suspicious TLD ─────────────────────────────────────────────────────
  let hasSuspiciousTLD = false;
  for (const tld of SUSPICIOUS_TLDS_HIGH) {
    if (domain.endsWith(tld)) {
      score += 22;
      hasSuspiciousTLD = true;
      reasons.push(`Uses a high-risk domain extension (${tld}) — commonly abused in phishing.`);
      break;
    }
  }
  if (!hasSuspiciousTLD) {
    for (const tld of SUSPICIOUS_TLDS_MEDIUM) {
      if (domain.endsWith(tld)) {
        score += 15;
        hasSuspiciousTLD = true;
        reasons.push(`Uses a suspicious domain extension (${tld}).`);
        break;
      }
    }
  }

  // ── 7. Combined: brand impersonation + suspicious TLD (+10 bonus) ──────────
  if ((hasBrandImpersonation || isTyposquat) && hasSuspiciousTLD) {
    score += 10;
    reasons.push('Combines brand impersonation with a risky domain extension.');
  }

  // ── 8. Credential keywords in URL — capped at 30 ──────────────────────────
  const credHits = CREDENTIAL_KEYWORDS.filter(kw => urlLow.includes(kw));
  if (credHits.length > 0) {
    score += Math.min(credHits.length * 15, 30);
    reasons.push(`High-risk keywords in URL: ${credHits.slice(0, 3).map(k => `"${k}"`).join(', ')}.`);
  }

  // ── 9. Lure keywords in URL — capped at 15 ────────────────────────────────
  const lureHits = LURE_KEYWORDS.filter(kw => urlLow.includes(kw));
  if (lureHits.length > 0) {
    score += Math.min(lureHits.length * 8, 15);
    reasons.push(`Lure keywords in URL: ${lureHits.slice(0, 3).map(k => `"${k}"`).join(', ')}.`);
  }

  // ── 10. No HTTPS (+15) ─────────────────────────────────────────────────────
  if (!url.startsWith('https')) {
    score += 15;
    reasons.push('Does not use HTTPS — your data could be intercepted.');
  }

  // ── 11. Very long URL (+8) ─────────────────────────────────────────────────
  if (url.length > 120) {
    score += 8;
    reasons.push('Unusually long URL — often used to hide malicious redirects.');
  }

  // ── 12. Excessive subdomains (+12) ────────────────────────────────────────
  if (domain.split('.').length > 4) {
    score += 12;
    reasons.push('Excessive subdomains — a trick to make phishing URLs look legitimate.');
  }

  // ── Classify ───────────────────────────────────────────────────────────────
  //   DANGEROUS  ≥ 80
  //   SUSPICIOUS ≥ 25
  //   SAFE       <  25
  let status;
  if      (score >= 80) status = 'DANGEROUS';
  else if (score >= 25) status = 'SUSPICIOUS';
  else                  status = 'SAFE';

  return { status, score, reasons: [...new Set(reasons)] };
}

// ─────────────────────────────────────────────
// SMS ANALYSIS  (recalibrated scoring)
// ─────────────────────────────────────────────

function analyzeSMS(text) {
  let score = 0;
  const reasons = [];
  const lower = text.toLowerCase();

  // ── Protective phrases (reduce score) ─────────────────────────────────────
  const PROTECTIVE = [
    'do not share', "don't share", 'never share',
    'do not click', "don't click", 'do not give', 'never give'
  ];
  let protection = 0;
  for (const p of PROTECTIVE) {
    if (lower.includes(p)) protection += 12;
  }

  // ── High-risk phrase patterns ──────────────────────────────────────────────
  const PHRASES = [
    { p: 'your account has been suspended',  s: 40 },
    { p: 'account suspended',                s: 32 },
    { p: 'account will be blocked',          s: 32 },
    { p: 'click here to verify',             s: 35 },
    { p: 'click here to claim',              s: 28 },
    { p: 'you have won',                     s: 35 },
    { p: 'congratulations you have',         s: 25 },
    { p: 'share your otp',                   s: 55 },
    { p: 'share your pin',                   s: 55 },
    { p: 'share your upi',                   s: 55 },
    { p: 'share your password',              s: 55 },
    { p: 'send your otp',                    s: 50 },
    { p: 'urgent action required',           s: 30 },
    { p: 'kyc update',                       s: 30 },
    { p: 'kyc verification',                 s: 28 },
    { p: 'free gift',                        s: 25 },
    { p: 'limited time offer',               s: 20 },
    { p: 'call now to claim',                s: 25 },
    { p: 'bank details',                     s: 30 },
    { p: 'upi pin',                          s: 45 },
    { p: 'verify your account',              s: 28 },
    { p: 'login to your account',            s: 25 },
    { p: 'your account needs verification',  s: 22 },
    { p: 'enter your otp',                   s: 12 },
    { p: 'otp',                              s: 10 },
  ];

  for (const { p, s } of PHRASES) {
    if (lower.includes(p)) {
      score += s;
      if (reasons.length < 4) reasons.push(`Contains suspicious phrase: "${p}"`);
    }
  }

  // ── Light keyword scan (catches phrasing not covered above) ───────────────
  const SMS_CRED_KW  = ['login', 'verify', 'verification', 'suspend', 'password', 'kyc', 'upi pin'];
  const SMS_LURE_KW  = ['winner', 'prize', 'claim', 'cashback', 'won'];
  const credHits = SMS_CRED_KW.filter(kw => lower.includes(kw));
  const lureHits = SMS_LURE_KW.filter(kw => lower.includes(kw));
  const kwScore = Math.min(credHits.length * 8, 18) + Math.min(lureHits.length * 5, 10);
  if (kwScore > 0) {
    score += kwScore;
    const hits = [...credHits, ...lureHits].slice(0, 3);
    if (reasons.length < 5) reasons.push(`Risky keywords: ${hits.join(', ')}`);
  }

  // ── Apply protective deduction ─────────────────────────────────────────────
  score = Math.max(0, score - protection);
  if (protection > 0) {
    reasons.push('Contains protective language (advises not to share info) — risk reduced.');
  }

  // ── Analyse any URLs embedded in the SMS ──────────────────────────────────
  const urls = text.match(/https?:\/\/[^\s]+/gi) || [];
  for (const url of urls) {
    const r = analyzeURL(url);
    score += Math.floor(r.score * 0.6);    // 60% of URL score contributes
    r.reasons.slice(0, 2).forEach(reason => {
      if (reasons.length < 7) reasons.push('[Link] ' + reason);
    });
  }

  // ── Classify ───────────────────────────────────────────────────────────────
  //   DANGEROUS  ≥ 60
  //   SUSPICIOUS ≥ 20
  //   SAFE       < 20
  let status;
  if      (score >= 60) status = 'DANGEROUS';
  else if (score >= 20) status = 'SUSPICIOUS';
  else                  status = 'SAFE';

  return { status, score, reasons: [...new Set(reasons)] };
}

// ─────────────────────────────────────────────
// MULTI-LANGUAGE RESULT MESSAGES
// ─────────────────────────────────────────────

const MESSAGES = {
  SAFE: {
    en: '✅ This looks SAFE. No phishing signals detected. Still, always stay cautious online.',
    hi: '✅ यह लिंक सुरक्षित दिखता है। कोई फ़िशिंग संकेत नहीं मिला। फिर भी हमेशा सावधान रहें।',
    ta: '✅ இது பாதுகாப்பானதாக தெரிகிறது. ஃபிஷிங் அறிகுறிகள் எதுவும் கண்டறியப்படவில்லை.',
    es: '✅ Esto parece SEGURO. No se detectaron señales de phishing. Aun así, mantén la precaución.',
    fr: '✅ Ceci semble SÛR. Aucun signal de phishing détecté. Restez néanmoins vigilant.',
    ar: '✅ يبدو هذا آمنًا. لم يتم اكتشاف أي إشارات تصيد احتيالي.',
  },
  SUSPICIOUS: {
    en: '⚠️ This looks SUSPICIOUS. Proceed with caution — do not enter any personal details.',
    hi: '⚠️ यह संदिग्ध लगता है। सावधानी से आगे बढ़ें — कोई भी व्यक्तिगत जानकारी न दें।',
    ta: '⚠️ இது சந்தேகமானதாக தெரிகிறது. எச்சரிக்கையாக இருங்கள் — தனிப்பட்ட விவரங்களை உள்ளிடாதீர்கள்.',
    es: '⚠️ Esto parece SOSPECHOSO. Proceda con precaución — no ingrese datos personales.',
    fr: '⚠️ Ceci semble SUSPECT. Soyez prudent — ne saisissez aucune information personnelle.',
    ar: '⚠️ يبدو هذا مشبوهًا. تصرف بحذر — لا تُدخل أي بيانات شخصية.',
  },
  DANGEROUS: {
    en: '🚨 DANGER! This is very likely a PHISHING attempt. Do NOT click, share, or enter any information!',
    hi: '🚨 खतरा! यह एक फिशिंग प्रयास है। क्लिक न करें, शेयर न करें, कोई जानकारी न दें!',
    ta: '🚨 ஆபத்து! இது ஃபிஷிங் முயற்சியாக இருக்கலாம். கிளிக் செய்யாதீர்கள், பகிராதீர்கள்!',
    es: '🚨 ¡PELIGRO! Esto es muy probablemente un intento de PHISHING. ¡NO haga clic ni comparta información!',
    fr: '🚨 DANGER ! Il s\'agit très probablement d\'une tentative de PHISHING. Ne cliquez pas et ne partagez rien !',
    ar: '🚨 خطر! هذا على الأرجح محاولة تصيد احتيالي. لا تنقر ولا تشارك أي معلومات!',
  },
};

function getMessage(status, lang = 'en') {
  return MESSAGES[status]?.[lang] ?? MESSAGES[status]?.['en'] ?? status;
}

// ─────────────────────────────────────────────
// CHATBOT  (keyword-based FAQ)
// ─────────────────────────────────────────────

const CHATBOT_REPLIES = {
  'what is phishing':
    'Phishing is when scammers trick you into revealing passwords, OTPs, or bank details using fake links or messages. They often impersonate banks, government agencies, or popular apps. 🎣',
  'how to stay safe':
    'Never share your OTP or PIN with anyone — not even bank employees. Always verify the link before clicking. When in doubt, call your bank on the official number. 🛡️',
  'what is otp':
    'OTP (One Time Password) is a secret code sent to your phone for verification. Never share it with anyone. Real banks never ask for your OTP! 🔐',
  'spot fake link':
    'Check for: misspellings (paypa1.com), suspicious endings (.xyz, .ml), very long URLs, and anything that is not HTTPS. When unsure, paste it in the Link Checker above. 🔍',
  'qr':
    'Scammers place fake QR codes on posters and emails. Always scan it with PhishGuard before visiting any link inside it. Receiving money never requires scanning a QR code. 📷',
  'clicked a bad link':
    'Stay calm! Immediately close the tab, do not enter any information, change your passwords, and contact your bank if you shared any details. 🆘',
  'is this safe':
    'Paste the link in the Link Checker above to find out instantly! 🔗',
  'what is upi':
    'UPI is a digital payment system. Your UPI PIN is only for sending money — entering a PIN is NEVER required to receive money. Anyone asking for your UPI PIN is a scammer. 💳',
  'suspicious message':
    'Do not click any links. Do not call back unknown numbers. Copy and paste the message text into the SMS Checker above. 📵',
  'i got a suspicious message':
    'Do not click any links. Do not call back unknown numbers. Copy and paste the message text into the SMS Checker above. 📵',
  'help':
    'I can help with phishing awareness, link safety, OTP safety, QR code scams, UPI scams, and more. Just ask me anything! 😊',
  'what is kyc':
    'KYC (Know Your Customer) is a legitimate bank process done in-person or through the official app/website. Banks never ask for KYC through SMS links or phone calls. 🏦',
  'lottery':
    'Real lotteries do not ask you to pay fees or share bank details to claim winnings. Any message claiming you "won" something is almost certainly a scam. 🎯',
};

function getChatbotReply(message) {
  const lower = message.toLowerCase();
  for (const key of Object.keys(CHATBOT_REPLIES)) {
    if (lower.includes(key)) return CHATBOT_REPLIES[key];
  }
  return "I'm not sure about that. Try asking: 'What is phishing?' or 'How to spot a fake link?' 🤔";
}

// ─────────────────────────────────────────────
// API ROUTES
// ─────────────────────────────────────────────

app.post('/api/check-link', (req, res) => {
  const { url, lang } = req.body;
  if (!url) return res.status(400).json({ error: 'URL is required' });
  const result = analyzeURL(url);
  result.message = getMessage(result.status, lang || 'en');
  result.url = url;
  res.json(result);
});

app.post('/api/check-sms', (req, res) => {
  const { text, lang } = req.body;
  if (!text) return res.status(400).json({ error: 'SMS text is required' });
  const result = analyzeSMS(text);
  result.message = getMessage(result.status, lang || 'en');
  res.json(result);
});

app.post('/api/check-qr', (req, res) => {
  const { url, lang } = req.body;
  if (!url) return res.status(400).json({ error: 'QR decoded URL is required' });
  const result = analyzeURL(url);
  result.message = getMessage(result.status, lang || 'en');
  result.source = 'QR Code';
  result.url = url;
  res.json(result);
});

app.post('/api/chatbot', (req, res) => {
  const { message } = req.body;
  if (!message) return res.status(400).json({ error: 'Message is required' });
  res.json({ reply: getChatbotReply(message) });
});

app.get('/api/health', (req, res) => {
  res.json({ status: 'PhishGuard server running ✅' });
});

// ─────────────────────────────────────────────
// SELF-TEST  (runs once on startup)
// ─────────────────────────────────────────────

function selfTest() {
  const cases = [
    // [input, expected, type]
    ['http://bit.ly/free-money-login',              'DANGEROUS',  'url'],
    ['http://192.168.0.1/verify-account',           'DANGEROUS',  'url'],
    ['http://paypal-secure-login.xyz/verify?id=123','DANGEROUS',  'url'],
    ['https://paypa1-secure-login.com',             'DANGEROUS',  'url'],
    ['https://google-login-security.xyz',           'DANGEROUS',  'url'],
    ['http://amazon-offer.click/deal',              'SUSPICIOUS', 'url'],
    ['http://secure-update-account.ml/login',       'SUSPICIOUS', 'url'],
    ['https://google.com',                          'SAFE',       'url'],
    ['https://amazon.in',                           'SAFE',       'url'],
    ['URGENT! Your SBI account has been suspended. Click here: http://sbi-verify.ml/login',  'DANGEROUS',  'sms'],
    ['You have won ₹50,000! Claim now: http://bit.ly/winner-claim', 'DANGEROUS', 'sms'],
    ['Your account needs verification. Please login soon.',          'SUSPICIOUS','sms'],
    ['Your OTP is 482193. Do not share it with anyone.',            'SAFE',      'sms'],
  ];

  let pass = 0, fail = 0;
  for (const [input, expected, type] of cases) {
    const result = type === 'sms' ? analyzeSMS(input) : analyzeURL(input);
    const ok = result.status === expected;
    if (ok) pass++;
    else {
      fail++;
      console.warn(`  ✗ [${type}] "${input.slice(0,60)}" → got ${result.status} (score ${result.score}), expected ${expected}`);
    }
  }
  console.log(`\n  Self-test: ${pass}/${pass + fail} passed${fail ? ' ⚠️' : ' ✅'}\n`);
}

// ─────────────────────────────────────────────
// START
// ─────────────────────────────────────────────

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n✅ PhishGuard running at http://localhost:${PORT}`);
  console.log(`   Open http://localhost:${PORT} in your browser\n`);
  selfTest();
});