const express = require('express');
const cors = require('cors');
const app = express();
app.get("/", (req, res) => {
  res.send("Phishing Detection API is running 🚀");
});
app.use(cors());
app.use(express.json());
app.use(express.json());

app.post("/check", (req, res) => {
  const { url } = req.body;

  if (!url) {
    return res.json({ status: "error", message: "No URL provided" });
  }

  if (url.includes("https")) {
    res.json({ status: "safe" });
  } else {
    res.json({ status: "phishing" });
  }
});// serves index.html, style.css, app.js

// ─────────────────────────────────────────────
// PHISHING DETECTION
// ─────────────────────────────────────────────

const DANGEROUS_KEYWORDS = [
  'verify', 'account', 'suspended', 'urgent', 'click', 'login',
  'password', 'otp', 'bank', 'kyc', 'update', 'prize', 'won',
  'free', 'limited', 'offer', 'credit', 'debit', 'upi', 'paytm',
  'refund', 'cashback', 'lucky', 'winner', 'claim', 'confirm'
];

const SUSPICIOUS_TLDS = [
  '.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.top',
  '.click', '.link', '.work', '.party', '.download'
];

const TRUSTED_DOMAINS = [
  'google.com', 'sbi.co.in', 'hdfcbank.com', 'icicibank.com',
  'axisbank.com', 'paytm.com', 'phonepe.com', 'npci.org.in',
  'gov.in', 'uidai.gov.in', 'irctc.co.in', 'amazon.in',
  'flipkart.com', 'youtube.com', 'facebook.com', 'instagram.com'
];

const PHISHING_PATTERNS = [
  /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/,
  /[a-z0-9]{30,}/,
  /@.*http/,
  /bit\.ly|tinyurl|t\.co|shorturl/i,
  /free.*money|money.*free/i,
  /your.*account.*suspend/i,
  /verify.*now|now.*verify/i,
  /click.*here.*win|win.*click/i,
];

function extractDomain(url) {
  try {
    if (!url.startsWith('http')) url = 'https://' + url;
    const u = new URL(url);
    return u.hostname.replace('www.', '');
  } catch {
    return url;
  }
}

function analyzeURL(url) {
  let score = 0;
  let reasons = [];
  const domain = extractDomain(url);
  const urlLower = url.toLowerCase();

  // FIXED: Check if the domain is a trusted domain or a subdomain of a trusted domain
  const isTrusted = TRUSTED_DOMAINS.some(d =>
    domain === d || domain.endsWith('.' + d)
  );
  if (isTrusted) {
    return { status: 'SAFE', score: 0, reasons: ['This is a known trusted website.'] };
  }

  if (/\d+\.\d+\.\d+\.\d+/.test(domain)) {
    score += 40;
    reasons.push('Uses a raw IP address instead of a proper website name.');
  }

  SUSPICIOUS_TLDS.forEach(tld => {
    if (domain.endsWith(tld)) {
      score += 25;
      reasons.push(`Uses a suspicious domain ending (${tld}).`);
    }
  });

  DANGEROUS_KEYWORDS.forEach(kw => {
    if (urlLower.includes(kw)) {
      score += 10;
      reasons.push(`Contains a suspicious word: "${kw}".`);
    }
  });

  PHISHING_PATTERNS.forEach(pattern => {
    if (pattern.test(url)) {
      score += 20;
      reasons.push('URL contains a suspicious pattern.');
    }
  });

  if (url.length > 100) {
    score += 10;
    reasons.push('URL is unusually long.');
  }

  if (!url.startsWith('https')) {
    score += 15;
    reasons.push('Website does not use a secure HTTPS connection.');
  }

  reasons = [...new Set(reasons)];

  let status;
  if (score >= 50)      status = 'DANGEROUS';
  else if (score >= 20) status = 'SUSPICIOUS';
  else                  status = 'SAFE';

  return { status, score, reasons };
}

function analyzeSMS(text) {
  let score = 0;
  let reasons = [];
  const lower = text.toLowerCase();

  const smsDangerPhrases = [
    { phrase: 'your account has been suspended', weight: 40 },
    { phrase: 'click here to verify',             weight: 35 },
    { phrase: 'you have won',                     weight: 35 },
    { phrase: 'share your otp',                   weight: 50 },
    { phrase: 'otp',                              weight: 15 },
    { phrase: 'urgent action required',           weight: 30 },
    { phrase: 'kyc update',                       weight: 30 },
    { phrase: 'free gift',                        weight: 25 },
    { phrase: 'limited time offer',               weight: 20 },
    { phrase: 'call now',                         weight: 15 },
    { phrase: 'bank details',                     weight: 30 },
    { phrase: 'upi pin',                          weight: 50 },
    { phrase: 'refund initiated',                 weight: 20 },
  ];

  smsDangerPhrases.forEach(({ phrase, weight }) => {
    if (lower.includes(phrase)) {
      score += weight;
      reasons.push(`Contains suspicious phrase: "${phrase}"`);
    }
  });

  const urlMatch = text.match(/https?:\/\/[^\s]+/gi);
  if (urlMatch) {
    urlMatch.forEach(url => {
      const urlResult = analyzeURL(url);
      score += urlResult.score / 2;
      reasons.push(...urlResult.reasons.map(r => `[Link in SMS] ${r}`));
    });
  }

  reasons = [...new Set(reasons)];

  let status;
  if (score >= 50)      status = 'DANGEROUS';
  else if (score >= 20) status = 'SUSPICIOUS';
  else                  status = 'SAFE';

  return { status, score, reasons };
}

// ─────────────────────────────────────────────
// MULTI-LANGUAGE MESSAGES
// ─────────────────────────────────────────────

const MESSAGES = {
  SAFE: {
    en: '✅ This link looks SAFE. You can proceed.',
    hi: '✅ यह लिंक सुरक्षित है। आप आगे जा सकते हैं।',
    ta: '✅ இந்த இணைப்பு பாதுகாப்பானது. நீங்கள் தொடரலாம்.',
    es: '✅ Este enlace parece SEGURO. Puede continuar.',
    fr: '✅ Ce lien semble SÛR. Vous pouvez continuer.',
    ar: '✅ هذا الرابط يبدو آمنًا. يمكنك المتابعة.',
  },
  SUSPICIOUS: {
    en: '⚠️ This link looks SUSPICIOUS. Be careful before clicking!',
    hi: '⚠️ यह लिंक संदिग्ध है। क्लिक करने से पहले सावधान रहें!',
    ta: '⚠️ இந்த இணைப்பு சந்தேகமானது. கவனமாக இருங்கள்!',
    es: '⚠️ Este enlace parece SOSPECHOSO. ¡Tenga cuidado!',
    fr: '⚠️ Ce lien semble SUSPECT. Soyez prudent avant de cliquer !',
    ar: '⚠️ هذا الرابط يبدو مشبوهًا. كن حذرًا قبل النقر!',
  },
  DANGEROUS: {
    en: '🚨 DANGER! This is likely a PHISHING link. Do NOT click or share!',
    hi: '🚨 खतरा! यह एक फिशिंग लिंक है। क्लिक या शेयर न करें!',
    ta: '🚨 ஆபத்து! இது ஃபிஷிங் இணைப்பு. கிளிக் செய்யாதீர்கள்!',
    es: '🚨 ¡PELIGRO! Este es un enlace de PHISHING. ¡NO haga clic!',
    fr: '🚨 DANGER ! C\'est un lien de PHISHING. Ne cliquez pas !',
    ar: '🚨 خطر! هذا رابط تصيد احتيالي. لا تنقر ولا تشارك!',
  }
};

function getMessage(status, lang = 'en') {
  return (MESSAGES[status][lang]) || MESSAGES[status]['en'];
}

// ─────────────────────────────────────────────
// CHATBOT
// ─────────────────────────────────────────────

const chatbotReplies = {
  'what is phishing':          'Phishing is when scammers trick you into giving your password, OTP, or bank details using fake links or messages. 🎣',
  'how to stay safe':          'Never share your OTP or PIN with anyone. Always check the link before clicking. When in doubt, call your bank directly. 🛡️',
  'what is otp':               'OTP (One Time Password) is a secret code sent to your phone. Never share it with anyone — not even bank employees! 🔐',
  'spot fake link':            'Look for misspellings in the domain (like "paypa1.com"), suspicious endings (.xyz, .ml), and very long URLs. 🔍',
  'qr':                        'Scammers put fake QR codes on posters and emails. Always use PhishGuard to check a QR code before visiting any link inside it. 📷',
  'clicked a bad link':        'Stay calm! Immediately close the page, do not enter any information, change your passwords, and contact your bank if needed. 🆘',
  'is this safe':              'Paste the link in the Link Checker above to find out instantly! 🔗',
  'what is upi':               'UPI is a payment system. Never share your UPI PIN with anyone. Receiving money never requires a PIN. 💳',
  'i got a suspicious message':'Do not click any links in it. Do not call back unknown numbers. Paste the message in the SMS checker above. 📵',
  'help':                      'I can help with: phishing awareness, link safety, OTP safety, QR code safety, UPI safety. Just ask! 😊',
};

function getChatbotReply(message) {
  const lower = message.toLowerCase();
  for (const key of Object.keys(chatbotReplies)) {
    if (lower.includes(key)) return chatbotReplies[key];
  }
  return "I'm not sure about that. Try asking: 'What is phishing?' or 'How to stay safe?' 🤔";
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
// START
// ─────────────────────────────────────────────

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ PhishGuard running at http://localhost:${PORT}`);
  console.log(`   Open http://localhost:${PORT} in your browser`);
});