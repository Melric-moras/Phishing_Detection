const express = require('express');
const cors = require('cors');
const app = express();

app.use(cors());
app.use(express.json());

// ─────────────────────────────────────────────
// PHISHING DETECTION LOGIC
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
  /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/,   // Raw IP address
  /[a-z0-9]{20,}/,                           // Very long random strings
  /@/,                                        // @ in URL (trick)
  /bit\.ly|tinyurl|t\.co|shorturl/i,         // URL shorteners
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

  // Check trusted domains
  const isTrusted = TRUSTED_DOMAINS.some(d => domain === d || domain.endsWith('.' + d));
  if (isTrusted) {
    return { status: 'SAFE', score: 0, reasons: ['This is a known trusted website.'] };
  }

  // Check raw IP
  if (/\d+\.\d+\.\d+\.\d+/.test(domain)) {
    score += 40;
    reasons.push('Uses a raw IP address instead of a proper website name.');
  }

  // Check suspicious TLDs
  SUSPICIOUS_TLDS.forEach(tld => {
    if (domain.endsWith(tld)) {
      score += 25;
      reasons.push(`Uses a suspicious domain ending (${tld}).`);
    }
  });

  // Check dangerous keywords
  DANGEROUS_KEYWORDS.forEach(kw => {
    if (urlLower.includes(kw)) {
      score += 10;
      reasons.push(`Contains a suspicious word: "${kw}".`);
    }
  });

  // Check phishing patterns
  PHISHING_PATTERNS.forEach(pattern => {
    if (pattern.test(url)) {
      score += 20;
      reasons.push('URL contains a suspicious pattern.');
    }
  });

  // Check URL length
  if (url.length > 100) {
    score += 10;
    reasons.push('URL is unusually long.');
  }

  // Check HTTPS
  if (!url.startsWith('https')) {
    score += 15;
    reasons.push('Website does not use secure HTTPS connection.');
  }

  // Deduplicate reasons
  reasons = [...new Set(reasons)];

  let status;
  if (score >= 50) status = 'DANGEROUS';
  else if (score >= 20) status = 'SUSPICIOUS';
  else status = 'SAFE';

  return { status, score, reasons };
}

// ─────────────────────────────────────────────
// MULTI-LANGUAGE MESSAGES
// ─────────────────────────────────────────────

const MESSAGES = {
  SAFE: {
    en: '✅ This link looks SAFE. You can proceed.',
    hi: '✅ यह लिंक सुरक्षित है। आप आगे जा सकते हैं।',
    kn: '✅ ಈ ಲಿಂಕ್ ಸುರಕ್ಷಿತವಾಗಿದೆ. ನೀವು ಮುಂದುವರಿಯಬಹುದು.',
    ta: '✅ இந்த இணைப்பு பாதுகாப்பானது. நீங்கள் தொடரலாம்.',
    te: '✅ ఈ లింక్ సురక్షితంగా ఉంది. మీరు కొనసాగవచ్చు.',
    mr: '✅ ही लिंक सुरक्षित आहे. आपण पुढे जाऊ शकता.',
  },
  SUSPICIOUS: {
    en: '⚠️ This link looks SUSPICIOUS. Be careful before clicking!',
    hi: '⚠️ यह लिंक संदिग्ध है। क्लिक करने से पहले सावधान रहें!',
    kn: '⚠️ ಈ ಲಿಂಕ್ ಅನುಮಾನಾಸ್ಪದವಾಗಿದೆ. ಕ್ಲಿಕ್ ಮಾಡುವ ಮೊದಲು ಎಚ್ಚರಿಕೆ!',
    ta: '⚠️ இந்த இணைப்பு சந்தேகமானது. கிளிக் செய்வதற்கு முன் கவனமாக இருங்கள்!',
    te: '⚠️ ఈ లింక్ అనుమానాస్పదంగా ఉంది. క్లిక్ చేయడానికి ముందు జాగ్రత్తగా ఉండండి!',
    mr: '⚠️ ही लिंक संशयास्पद आहे. क्लिक करण्यापूर्वी सावधान राहा!',
  },
  DANGEROUS: {
    en: '🚨 DANGER! This is likely a PHISHING link. Do NOT click or share!',
    hi: '🚨 खतरा! यह एक फिशिंग लिंक है। क्लिक या शेयर न करें!',
    kn: '🚨 ಅಪಾಯ! ಇದು ಫಿಶಿಂಗ್ ಲಿಂಕ್ ಆಗಿದೆ. ಕ್ಲಿಕ್ ಅಥವಾ ಶೇರ್ ಮಾಡಬೇಡಿ!',
    ta: '🚨 ஆபத்து! இது ஒரு ஃபிஷிங் இணைப்பு. கிளிக் செய்யவோ பகிரவோ வேண்டாம்!',
    te: '🚨 ప్రమాదం! ఇది ఫిషింగ్ లింక్. క్లిక్ చేయవద్దు లేదా షేర్ చేయవద్దు!',
    mr: '🚨 धोका! हे एक फिशिंग लिंक आहे. क्लिक करू नका किंवा शेअर करू नका!',
  }
};

function getMessage(status, lang = 'en') {
  const langMap = MESSAGES[status];
  return langMap[lang] || langMap['en'];
}

// ─────────────────────────────────────────────
// SMS PHISHING DETECTION
// ─────────────────────────────────────────────

function analyzeSMS(text) {
  let score = 0;
  let reasons = [];
  const lower = text.toLowerCase();

  const smsDangerPhrases = [
    { phrase: 'your account has been suspended', weight: 40 },
    { phrase: 'click here to verify', weight: 35 },
    { phrase: 'you have won', weight: 35 },
    { phrase: 'otp', weight: 15 },
    { phrase: 'share your otp', weight: 50 },
    { phrase: 'urgent action required', weight: 30 },
    { phrase: 'kyc update', weight: 30 },
    { phrase: 'free gift', weight: 25 },
    { phrase: 'limited time offer', weight: 20 },
    { phrase: 'call now', weight: 15 },
    { phrase: 'bank details', weight: 30 },
    { phrase: 'upi pin', weight: 50 },
    { phrase: 'refund initiated', weight: 20 },
  ];

  smsDangerPhrases.forEach(({ phrase, weight }) => {
    if (lower.includes(phrase)) {
      score += weight;
      reasons.push(`Contains suspicious phrase: "${phrase}"`);
    }
  });

  // Check for URLs inside SMS
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
  if (score >= 50) status = 'DANGEROUS';
  else if (score >= 20) status = 'SUSPICIOUS';
  else status = 'SAFE';

  return { status, score, reasons };
}

// ─────────────────────────────────────────────
// SIMPLE AI CHATBOT RESPONSES
// ─────────────────────────────────────────────

const chatbotReplies = {
  'what is phishing': 'Phishing is when scammers trick you into giving your password, OTP, or bank details using fake links or messages.',
  'how to stay safe': 'Never share your OTP or PIN with anyone. Always check the link before clicking. When in doubt, call your bank directly.',
  'what is otp': 'OTP (One Time Password) is a secret code sent to your phone. Never share it with anyone — not even bank employees!',
  'is this safe': 'Paste the link above in the link checker to find out if it is safe!',
  'what is upi': 'UPI is a payment system. Never share your UPI PIN with anyone. Receiving money never requires a PIN.',
  'i got a suspicious message': 'Do not click any links in it. Do not call back unknown numbers. You can paste the message in our SMS checker above.',
  'help': 'I can help you with: phishing awareness, link safety, OTP safety, UPI safety. Just ask me anything!',
};

function getChatbotReply(message) {
  const lower = message.toLowerCase();
  for (const key of Object.keys(chatbotReplies)) {
    if (lower.includes(key)) return chatbotReplies[key];
  }
  return "I'm not sure about that. Try asking: 'What is phishing?' or 'How to stay safe?'";
}

// ─────────────────────────────────────────────
// API ROUTES
// ─────────────────────────────────────────────

// 1. CHECK LINK
app.post('/api/check-link', (req, res) => {
  const { url, lang } = req.body;
  if (!url) return res.status(400).json({ error: 'URL is required' });

  const result = analyzeURL(url);
  result.message = getMessage(result.status, lang || 'en');
  result.url = url;

  res.json(result);
});

// 2. CHECK SMS
app.post('/api/check-sms', (req, res) => {
  const { text, lang } = req.body;
  if (!text) return res.status(400).json({ error: 'SMS text is required' });

  const result = analyzeSMS(text);
  result.message = getMessage(result.status, lang || 'en');

  res.json(result);
});

// 3. CHECK QR (QR gives a URL after scanning — send that URL here)
app.post('/api/check-qr', (req, res) => {
  const { url, lang } = req.body;
  if (!url) return res.status(400).json({ error: 'QR decoded URL is required' });

  const result = analyzeURL(url);
  result.message = getMessage(result.status, lang || 'en');
  result.source = 'QR Code';
  result.url = url;

  res.json(result);
});

// 4. CHATBOT
app.post('/api/chatbot', (req, res) => {
  const { message } = req.body;
  if (!message) return res.status(400).json({ error: 'Message is required' });

  const reply = getChatbotReply(message);
  res.json({ reply });
});

// 5. HEALTH CHECK
app.get('/api/health', (req, res) => {
  res.json({ status: 'Server is running ✅' });
});

// ─────────────────────────────────────────────
// START SERVER
// ─────────────────────────────────────────────

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`✅ Phishing Guard Server running on http://localhost:${PORT}`);
});