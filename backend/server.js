const express = require('express');
const cors    = require('cors');
const path    = require('path');
const app     = express();

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../frontend')));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, '../frontend/index.html')));

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
  'razorpay.com', 'billdesk.com', 'rbi.org.in',
];

const BRAND_NAMES = [
  'paypal', 'sbi', 'hdfc', 'icici', 'axis', 'google', 'facebook',
  'amazon', 'apple', 'microsoft', 'netflix', 'paytm', 'phonepe',
  'whatsapp', 'instagram', 'twitter', 'linkedin', 'uber', 'ola',
  'zomato', 'swiggy', 'razorpay',
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

const TYPOSQUAT_PATTERNS = [
  { pattern: /paypa[l1i][-.]|paypa[l1i][^a-z0-9]/i, brand: 'PayPal'    },
  { pattern: /g[o0]{2}g[l1e]e|g[o0]gle/i,           brand: 'Google'    },
  { pattern: /faceb[o0]{2}k|facebok/i,               brand: 'Facebook'  },
  { pattern: /amaz0n|arnazon|anazon/i,               brand: 'Amazon'    },
  { pattern: /micros[o0]ft|mircosoft/i,              brand: 'Microsoft' },
  { pattern: /app1e|appl3|aple\./i,                  brand: 'Apple'     },
  { pattern: /inst[a4]gr[a4]m/i,                     brand: 'Instagram' },
  { pattern: /linkedln|1inkedin|linkdin/i,           brand: 'LinkedIn'  },
  { pattern: /wh[a4]ts[a4]pp/i,                      brand: 'WhatsApp'  },
];

const URL_SHORTENER_RE     = /^(bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly|shorturl\.|rb\.gy|cutt\.ly|tiny\.cc|s\.id|v\.gd)$/i;
const SUSPICIOUS_TLDS_HIGH   = ['.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw'];
const SUSPICIOUS_TLDS_MEDIUM = ['.click', '.link', '.top', '.work', '.party', '.download', '.loan', '.win', '.bid'];

const CREDENTIAL_KEYWORDS = [
  'login', 'verify', 'verification', 'account', 'password', 'otp',
  'kyc', 'confirm', 'suspend', 'suspended', 'upi', 'pin', 'secure',
  'security', 'authenticate', 'validation', 'reactivate', 'update',
];

const LURE_KEYWORDS = [
  'free', 'offer', 'prize', 'winner', 'won', 'claim',
  'cashback', 'refund', 'limited', 'deal', 'lucky', 'reward',
  'gift', 'bonus', 'earn', 'money', 'cash',
];

// ─────────────────────────────────────────────
// URL ANALYSIS
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
  let score = 0;
  const reasons = [];
  const domain  = extractDomain(url);
  const urlLow  = url.toLowerCase();

  const trusted = TRUSTED_DOMAINS.some(d => domain === d || domain.endsWith('.' + d));
  if (trusted) return { status: 'SAFE', score: 0, reasons: ['Verified trusted website.'] };

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(domain)) {
    score += 45;
    reasons.push('Uses a raw IP address — legitimate websites always use a domain name.');
  }

  const domainNoPort = domain.split(':')[0];
  if (URL_SHORTENER_RE.test(domainNoPort)) {
    score += 50;
    reasons.push('Uses a URL shortener that hides the real destination.');
  }

  let isTyposquat = false;
  for (const { pattern, brand } of TYPOSQUAT_PATTERNS) {
    if (pattern.test(domain)) {
      score += 55; isTyposquat = true;
      reasons.push(`Misspells "${brand}"'s domain — classic typosquatting to steal credentials.`);
      break;
    }
  }

  let hasBrandImpersonation = false;
  if (!isTyposquat) {
    for (const brand of BRAND_NAMES) {
      if (domain.includes(brand)) {
        const officials  = BRAND_OFFICIAL_DOMAINS[brand] || [];
        const isOfficial = officials.some(d => domain === d || domain.endsWith('.' + d));
        if (!isOfficial) {
          score += 20; hasBrandImpersonation = true;
          reasons.push(`Contains "${brand}" but is not the official ${brand} website.`);
          break;
        }
      }
    }
  }

  let hasSuspiciousTLD = false;
  for (const tld of SUSPICIOUS_TLDS_HIGH) {
    if (domain.endsWith(tld)) {
      score += 22; hasSuspiciousTLD = true;
      reasons.push(`Uses a high-risk domain extension (${tld}) — commonly abused in phishing.`);
      break;
    }
  }
  if (!hasSuspiciousTLD) {
    for (const tld of SUSPICIOUS_TLDS_MEDIUM) {
      if (domain.endsWith(tld)) {
        score += 15; hasSuspiciousTLD = true;
        reasons.push(`Uses a suspicious domain extension (${tld}).`);
        break;
      }
    }
  }

  if ((hasBrandImpersonation || isTyposquat) && hasSuspiciousTLD) {
    score += 10;
    reasons.push('Combines brand impersonation with a risky domain extension.');
  }

  const credHits = CREDENTIAL_KEYWORDS.filter(kw => urlLow.includes(kw));
  if (credHits.length > 0) {
    score += Math.min(credHits.length * 15, 30);
    reasons.push(`High-risk keywords in URL: ${credHits.slice(0, 3).map(k => `"${k}"`).join(', ')}.`);
  }

  const lureHits = LURE_KEYWORDS.filter(kw => urlLow.includes(kw));
  if (lureHits.length > 0) {
    score += Math.min(lureHits.length * 8, 15);
    reasons.push(`Lure keywords in URL: ${lureHits.slice(0, 3).map(k => `"${k}"`).join(', ')}.`);
  }

  if (!url.startsWith('https')) { score += 15; reasons.push('Does not use HTTPS — data could be intercepted.'); }
  if (url.length > 120)         { score += 8;  reasons.push('Unusually long URL — used to hide malicious redirects.'); }
  if (domain.split('.').length > 4) { score += 12; reasons.push('Excessive subdomains — tricks users into trusting the URL.'); }

  let status;
  if      (score >= 80) status = 'DANGEROUS';
  else if (score >= 25) status = 'SUSPICIOUS';
  else                  status = 'SAFE';

  return { status, score, reasons: [...new Set(reasons)] };
}

// ─────────────────────────────────────────────
// SMS ANALYSIS
// ─────────────────────────────────────────────

function analyzeSMS(text) {
  let score = 0;
  const reasons = [];
  const lower = text.toLowerCase();

  const PROTECTIVE = ['do not share', "don't share", 'never share', 'do not click', "don't click", 'do not give', 'never give'];
  let protection = 0;
  for (const p of PROTECTIVE) { if (lower.includes(p)) protection += 12; }

  const PHRASES = [
    { p: 'your account has been suspended', s: 40 },
    { p: 'account suspended',               s: 32 },
    { p: 'account will be blocked',         s: 32 },
    { p: 'click here to verify',            s: 35 },
    { p: 'click here to claim',             s: 28 },
    { p: 'you have won',                    s: 35 },
    { p: 'congratulations you have',        s: 25 },
    { p: 'share your otp',                  s: 55 },
    { p: 'share your pin',                  s: 55 },
    { p: 'share your upi',                  s: 55 },
    { p: 'share your password',             s: 55 },
    { p: 'send your otp',                   s: 50 },
    { p: 'urgent action required',          s: 30 },
    { p: 'kyc update',                      s: 30 },
    { p: 'kyc verification',                s: 28 },
    { p: 'free gift',                       s: 25 },
    { p: 'limited time offer',              s: 20 },
    { p: 'call now to claim',               s: 25 },
    { p: 'bank details',                    s: 30 },
    { p: 'upi pin',                         s: 45 },
    { p: 'verify your account',             s: 28 },
    { p: 'login to your account',           s: 25 },
    { p: 'your account needs verification', s: 22 },
    { p: 'enter your otp',                  s: 12 },
    { p: 'otp',                             s: 10 },
  ];

  for (const { p, s } of PHRASES) {
    if (lower.includes(p)) {
      score += s;
      if (reasons.length < 4) reasons.push(`Contains suspicious phrase: "${p}"`);
    }
  }

  const credHits = ['login', 'verify', 'verification', 'suspend', 'password', 'kyc', 'upi pin'].filter(kw => lower.includes(kw));
  const lureHits = ['winner', 'prize', 'claim', 'cashback', 'won'].filter(kw => lower.includes(kw));
  const kwScore  = Math.min(credHits.length * 8, 18) + Math.min(lureHits.length * 5, 10);
  if (kwScore > 0) {
    score += kwScore;
    if (reasons.length < 5) reasons.push(`Risky keywords: ${[...credHits, ...lureHits].slice(0, 3).join(', ')}`);
  }

  score = Math.max(0, score - protection);
  if (protection > 0) reasons.push('Contains protective language — risk reduced.');

  const urls = text.match(/https?:\/\/[^\s]+/gi) || [];
  for (const url of urls) {
    const r = analyzeURL(url);
    score += Math.floor(r.score * 0.6);
    r.reasons.slice(0, 2).forEach(reason => {
      if (reasons.length < 7) reasons.push('[Link] ' + reason);
    });
  }

  let status;
  if      (score >= 60) status = 'DANGEROUS';
  else if (score >= 20) status = 'SUSPICIOUS';
  else                  status = 'SAFE';

  return { status, score, reasons: [...new Set(reasons)] };
}

// ─────────────────────────────────────────────
// MULTI-LANGUAGE RESULT MESSAGES
// NOTE: No emojis — these strings are spoken aloud by the browser TTS
// ─────────────────────────────────────────────

const MESSAGES = {
  SAFE: {
    en: 'This looks safe. No phishing signals detected. Still, always stay cautious online.',
    hi: 'यह लिंक सुरक्षित दिखता है। कोई फिशिंग संकेत नहीं मिला। फिर भी हमेशा सावधान रहें।',
    ta: 'இது பாதுகாப்பானதாக தெரிகிறது. ஃபிஷிங் அறிகுறிகள் எதுவும் கண்டறியப்படவில்லை.',
    es: 'Esto parece seguro. No se detectaron señales de phishing. Mantén la precaución.',
    fr: 'Ceci semble sûr. Aucun signal de phishing détecté. Restez néanmoins vigilant.',
    ar: 'يبدو هذا آمنًا. لم يتم اكتشاف أي إشارات تصيد احتيالي.',
  },
  SUSPICIOUS: {
    en: 'This looks suspicious. Proceed with caution and do not enter any personal details.',
    hi: 'यह संदिग्ध लगता है। सावधानी से आगे बढ़ें और कोई भी व्यक्तिगत जानकारी न दें।',
    ta: 'இது சந்தேகமானதாக தெரிகிறது. எச்சரிக்கையாக இருங்கள், தனிப்பட்ட விவரங்களை உள்ளிடாதீர்கள்.',
    es: 'Esto parece sospechoso. Proceda con precaución y no ingrese datos personales.',
    fr: 'Ceci semble suspect. Soyez prudent et ne saisissez aucune information personnelle.',
    ar: 'يبدو هذا مشبوهًا. تصرف بحذر ولا تدخل أي بيانات شخصية.',
  },
  DANGEROUS: {
    en: 'Danger! This is very likely a phishing attempt. Do not click, share, or enter any information!',
    hi: 'खतरा! यह एक फिशिंग प्रयास है। क्लिक न करें, शेयर न करें, कोई जानकारी न दें!',
    ta: 'ஆபத்து! இது ஃபிஷிங் முயற்சியாக இருக்கலாம். கிளிக் செய்யாதீர்கள், பகிராதீர்கள்!',
    es: 'Peligro! Esto es muy probablemente un intento de phishing. No haga clic ni comparta información!',
    fr: 'Danger! Il s\'agit très probablement d\'une tentative de phishing. Ne cliquez pas et ne partagez rien!',
    ar: 'خطر! هذا على الأرجح محاولة تصيد احتيالي. لا تنقر ولا تشارك أي معلومات!',
  },
};

function getMessage(status, lang = 'en') {
  return MESSAGES[status]?.[lang] ?? MESSAGES[status]?.['en'] ?? status;
}

// ─────────────────────────────────────────────
// AI CHATBOT — powered by Claude (Anthropic API)
// ─────────────────────────────────────────────
//
// HOW TO ENABLE:
//   export ANTHROPIC_API_KEY="sk-ant-..."
//   node server.js
//
// Without the key the chatbot uses a smart topic-aware fallback
// that handles open-ended natural language questions.
// ─────────────────────────────────────────────

const CHATBOT_SYSTEM_PROMPT = `You are PhishGuard AI, a friendly cybersecurity assistant focused on phishing awareness and online safety.

YOUR PURPOSE:
Help users understand phishing, online scams, and how to stay safe. Be generous about what counts as in-scope — if a question is even loosely related to online fraud, scams, cybersecurity, or digital safety, answer it helpfully.

IN-SCOPE TOPICS (answer all of these freely):
- What phishing is, how it works, why scammers do it, how they benefit
- How to spot fake links, fake websites, phishing emails, fake SMS
- OTP safety — what it is, why never share it, how OTP scams work
- UPI and mobile payment scams
- QR code scams
- KYC fraud
- Social engineering and psychological manipulation by scammers
- What to do after clicking a bad link or sharing details by mistake
- How to report scams in India
- General online safety and password hygiene
- Any variation, follow-up, or creative phrasing of the above

STYLE:
- Give real, complete, helpful answers
- 2 to 5 sentences, plain conversational language
- No markdown, no bullet points, no asterisks, no emojis (replies are read aloud)
- Sound calm, reassuring and knowledgeable

OUT OF SCOPE:
- If someone asks something genuinely unrelated to online safety, scams, or cybersecurity (like recipes, sports, entertainment), respond with: "I am only able to help with phishing and online safety topics. Feel free to ask me anything about scams, fake links, OTP safety, or how to protect yourself online."

LANGUAGE RULE:
Reply in the SAME language the user writes in. Hindi gets Hindi. Tamil gets Tamil.`;

async function getAIChatbotReply(message) {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    console.log('  [chatbot] No ANTHROPIC_API_KEY — using smart fallback');
    return getSmartFallbackReply(message);
  }
  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method:  'POST',
      headers: {
        'Content-Type':      'application/json',
        'x-api-key':         apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model:      'claude-haiku-4-5-20251001',
        max_tokens: 400,
        system:     CHATBOT_SYSTEM_PROMPT,
        messages:   [{ role: 'user', content: message }],
      }),
    });
    if (!response.ok) {
      const errText = await response.text();
      console.error('Anthropic API error:', response.status, errText);
      return getSmartFallbackReply(message);
    }
    const data  = await response.json();
    const reply = data.content?.[0]?.text?.trim();
    return reply || getSmartFallbackReply(message);
  } catch (err) {
    console.error('Chatbot fetch failed:', err.message);
    return getSmartFallbackReply(message);
  }
}

// ─────────────────────────────────────────────
// SMART FALLBACK — topic-aware natural language matcher
// ─────────────────────────────────────────────

const TOPICS = [
  {
    id: 'what_is_phishing',
    triggers: [
      'what is phishing', 'what phishing', 'define phishing', 'phishing mean',
      'how does phishing work', 'phishing work', 'explain phishing', 'how phishing',
      'phishing attacks', 'types of phishing', 'why phishing', 'benefit scammer',
      'benefit from phishing', 'scammer benefit', 'gain from phishing',
      'why do scammer', 'how scammer make money', 'how do scammer',
      'profit from phishing', 'how does scammer', 'scammer earn',
      'why do people phish',
    ],
    reply: 'Phishing is when scammers send fake messages or create fake websites to trick you into giving up your passwords, OTP, or bank details. Scammers benefit by stealing money directly from your account, selling your personal data to other criminals, or using your identity to commit further fraud. They disguise themselves as trusted organisations like banks, government agencies, or popular apps to make the message seem legitimate. The goal is always to make you act quickly without thinking.',
  },
  {
    id: 'spot_fake_link',
    triggers: [
      'spot fake', 'fake link', 'identify fake', 'tell if link', 'check link',
      'how to check link', 'is this link safe', 'link safe', 'unsafe link',
      'how do i spot', 'recognise phishing', 'detect phishing', 'fake website',
      'tell fake', 'suspicious link', 'look fake', 'how to identify',
      'verify link', 'check url', 'url safe', 'link real', 'real website',
      'fake domain', 'spoof website', 'phishing website',
    ],
    reply: 'To spot a fake link, look carefully at the domain name — scammers use misspellings like paypa1.com or g00gle.com. Be suspicious of unusual endings like .xyz, .ml, or .tk, which are free domains commonly used in scams. Real banks and companies always use HTTPS and their official domain. If the URL is unusually long, has random characters, or was sent to you unexpectedly, do not click it. Paste it into the Link Checker above for an instant analysis.',
  },
  {
    id: 'otp_safety',
    triggers: [
      'otp', 'one time password', 'otp safe', 'share otp', 'give otp',
      'safe to share', 'should i share', 'share my otp', 'otp danger',
      'otp scam', 'otp fraud', 'otp asked', 'bank ask otp',
      'is otp', 'why not share otp', 'otp meaning', 'what is otp',
      'otp someone asking', 'asked for otp', 'caller asked otp',
    ],
    reply: 'Your OTP (One Time Password) should never be shared with anyone — not with someone calling from a bank, not with a company representative, not with anyone at all. No legitimate bank, company, or government office will ever call or message you asking for your OTP. The moment you share your OTP, a scammer can instantly access your account and transfer money. If someone asks for your OTP, end the call immediately and contact your bank on their official number.',
  },
  {
    id: 'upi_safety',
    triggers: [
      'upi', 'upi pin', 'upi scam', 'upi fraud', 'payment scam',
      'gpay', 'phonepe', 'paytm', 'receive money pin', 'scan to receive',
      'money transfer scam', 'digital payment', 'online payment safe',
      'upi safe', 'how upi scam', 'mobile payment', 'send money scam',
    ],
    reply: 'Your UPI PIN is only required when sending money — you never need to enter any PIN to receive money. Scammers often trick victims by saying they are sending a refund or prize and ask you to enter your PIN or scan a QR code to accept it. This is always a scam. Only use payment apps downloaded from official app stores, and never share your UPI PIN with anyone over call, SMS, or chat.',
  },
  {
    id: 'qr_scam',
    triggers: [
      'qr code', 'qr scam', 'scan qr', 'qr fraud', 'qr phishing',
      'fake qr', 'malicious qr', 'qr link', 'unsafe qr', 'qr code safe',
      'how qr scam', 'qr code scammer', 'qr on poster',
    ],
    reply: 'Scammers place fake QR codes over real ones on posters, menus, and parking machines. Scanning a malicious QR code can take you to a phishing website designed to steal your login details, or it can trigger an automatic payment from your phone. Always verify where a QR code leads before entering any information. Remember — receiving money never requires you to scan a QR code.',
  },
  {
    id: 'kyc_scam',
    triggers: [
      'kyc', 'know your customer', 'kyc update', 'kyc verification',
      'kyc expired', 'kyc link', 'kyc sms', 'kyc call', 'kyc scam',
      'complete kyc', 'kyc blocked', 'account blocked kyc',
    ],
    reply: 'KYC or Know Your Customer is a real verification process that banks use. However, banks always do it in-person at a branch, through their official app, or on their official website — never through an SMS link or a phone call from an unknown number. Any message saying your account will be blocked unless you update KYC by clicking a link is a phishing scam.',
  },
  {
    id: 'clicked_bad_link',
    triggers: [
      'clicked', 'already clicked', 'i clicked', 'opened link', 'visited link',
      'entered details', 'gave my details', 'what do i do', 'what should i do',
      'i shared', 'i gave', 'accidentally', 'by mistake', 'already shared',
      'shared my otp', 'gave otp', 'entered my password', 'filled form',
    ],
    reply: 'Stay calm and act immediately. Close the suspicious tab or app right away and change your passwords for your bank account, email, and any other important accounts as fast as possible. If you entered any banking details, OTP, or PIN, call your bank immediately on their official customer care number to freeze or block your account. Report the incident to the national cybercrime helpline at 1930 or cybercrime.gov.in.',
  },
  {
    id: 'email_phishing',
    triggers: [
      'phishing email', 'fake email', 'suspicious email', 'scam email',
      'email scam', 'email fraud', 'fake mail', 'malicious email',
      'spam email', 'email attachment', 'email link', 'spoofed email',
    ],
    reply: 'Phishing emails look like they come from trusted sources like your bank, a courier company, or a government office. Always check the sender email address carefully — it often contains random characters or a slightly wrong domain. Never click links or download attachments from unexpected emails. If you are unsure, go directly to the official website by typing the address yourself in the browser.',
  },
  {
    id: 'voice_vishing',
    triggers: [
      'phone call scam', 'vishing', 'fake call', 'scam call', 'call from bank',
      'unknown caller', 'caller asking', 'phone fraud', 'call fraud',
      'voice scam', 'someone called', 'got a call', 'call saying',
    ],
    reply: 'Voice phishing or vishing is when scammers call you pretending to be from your bank, government, or a tech company. Real banks never call asking for your OTP, PIN, or full card number over the phone. If you receive such a call, hang up immediately and call your bank back using the number printed on the back of your card or on their official website.',
  },
  {
    id: 'social_engineering',
    triggers: [
      'social engineering', 'manipulation', 'psychological trick', 'trick people',
      'how scammer trick', 'why people fall', 'people get scammed',
      'impersonation', 'pretend to be', 'fake identity', 'urgency tactic',
      'pressure tactic', 'fear tactic', 'how scammer convince',
    ],
    reply: 'Social engineering is the art of manipulating people psychologically rather than hacking computers. Scammers exploit emotions like fear, urgency, greed, and trust to make you act without thinking. A message saying your account will be blocked in one hour is designed to cause panic so you click without checking. Recognising this pressure tactic is your best defence — always pause, take a breath, and verify through official channels before doing anything.',
  },
  {
    id: 'report_scam',
    triggers: [
      'report scam', 'report fraud', 'how to report', 'where to report',
      'complain about scam', 'file complaint', 'cybercrime helpline',
      'report phishing', 'report to bank', 'lodge complaint',
    ],
    reply: 'In India, you can report cybercrime online at cybercrime.gov.in or call the national helpline 1930. Contact your bank immediately on their official customer care number — acting within the first 24 hours gives the best chance of recovering lost money. Also file a complaint at your nearest police station and keep screenshots of the scam as evidence.',
  },
  {
    id: 'stay_safe',
    triggers: [
      'stay safe', 'how to be safe', 'protect myself', 'protect account',
      'online safety', 'safety tips', 'prevent phishing', 'avoid scam',
      'best practices', 'security tips', 'be careful online',
      'how to avoid', 'how to prevent', 'safety measures',
    ],
    reply: 'The most important rules for staying safe online are: never share your OTP, PIN, or password with anyone for any reason. Always verify a link before clicking — use PhishGuard for instant checking. Be suspicious of any message that creates urgency or offers something too good to be true. Enable two-factor authentication on your bank and email accounts and use strong unique passwords.',
  },
  {
    id: 'help',
    triggers: [
      'help', 'what can you do', 'what can i ask', 'capabilities',
      'tell me about yourself', 'what do you know',
    ],
    reply: 'I am PhishGuard AI, your online safety assistant. You can ask me anything about phishing scams, how to spot fake links, OTP and UPI safety, QR code fraud, KYC scams, voice call scams, what to do after clicking a bad link, and how to report cybercrime. Ask any question in your own words and I will do my best to help.',
  },
];

const PHISHING_SIGNAL_WORDS = [
  'phish', 'scam', 'fraud', 'fake', 'suspicious', 'hack', 'steal',
  'password', 'credential', 'otp', 'pin', 'upi', 'kyc', 'bank',
  'account', 'link', 'url', 'email', 'sms', 'qr', 'virus', 'malware',
  'safe', 'danger', 'warning', 'block', 'suspend', 'verify', 'click',
  'scammer', 'criminal', 'cybercrime', 'identity', 'theft', 'data',
  'trick', 'cheat', 'money', 'transfer', 'debit', 'credit',
  'clicked', 'opened', 'shared', 'gave', 'entered', 'accident',
  'smishing', 'vishing', 'spam', 'malware', 'ransomware', 'hacker',
  'security', 'privacy', 'protect', 'attack', 'breach', 'leak',
];

function getSmartFallbackReply(message) {
  const lower = message.toLowerCase();
  for (const topic of TOPICS) {
    for (const trigger of topic.triggers) {
      if (lower.includes(trigger)) return topic.reply;
    }
  }
  const hasSignal = PHISHING_SIGNAL_WORDS.some(w => lower.includes(w));
  if (hasSignal) {
    return 'That is a great online safety question. In general, always be cautious of any message that creates urgency, asks for personal details like OTP or PIN, or contains links from unknown sources. You can paste any link or suspicious message into PhishGuard above for an instant analysis. If you have already shared sensitive details, contact your bank immediately.';
  }
  return 'I am only able to help with phishing and online safety topics. Feel free to ask me anything about scams, fake links, OTP safety, QR code fraud, or how to protect yourself online.';
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

app.post('/api/chatbot', async (req, res) => {
  const { message } = req.body;
  if (!message) return res.status(400).json({ error: 'Message is required' });
  try {
    const reply = await getAIChatbotReply(message);
    res.json({ reply });
  } catch (err) {
    console.error('Chatbot error:', err);
    res.json({ reply: getFallbackReply(message) });
  }
});

app.get('/api/health', (req, res) => {
  res.json({
    status:     'PhishGuard server running',
    ai_chatbot: process.env.ANTHROPIC_API_KEY
      ? 'enabled — Claude AI'
      : 'fallback mode — set ANTHROPIC_API_KEY to enable AI chat',
  });
});

// ─────────────────────────────────────────────
// SELF-TEST
// ─────────────────────────────────────────────

function selfTest() {
  const cases = [
    ['http://bit.ly/free-money-login',               'DANGEROUS',  'url'],
    ['http://192.168.0.1/verify-account',            'DANGEROUS',  'url'],
    ['http://paypal-secure-login.xyz/verify?id=123', 'DANGEROUS',  'url'],
    ['https://paypa1-secure-login.com',              'DANGEROUS',  'url'],
    ['https://google-login-security.xyz',            'DANGEROUS',  'url'],
    ['http://amazon-offer.click/deal',               'SUSPICIOUS', 'url'],
    ['http://secure-update-account.ml/login',        'SUSPICIOUS', 'url'],
    ['https://google.com',                           'SAFE',       'url'],
    ['https://amazon.in',                            'SAFE',       'url'],
    ['URGENT! Your SBI account has been suspended. Click here: http://sbi-verify.ml/login', 'DANGEROUS', 'sms'],
    ['You have won Rs 50000! Claim now: http://bit.ly/winner-claim',                        'DANGEROUS', 'sms'],
    ['Your account needs verification. Please login soon.',                                 'SUSPICIOUS','sms'],
    ['Your OTP is 482193. Do not share it with anyone.',                                    'SAFE',      'sms'],
  ];

  let pass = 0, fail = 0;
  for (const [input, expected, type] of cases) {
    const result = type === 'sms' ? analyzeSMS(input) : analyzeURL(input);
    const ok = result.status === expected;
    if (ok) pass++;
    else {
      fail++;
      console.warn(`  ✗ [${type}] "${input.slice(0, 60)}" → got ${result.status} (score ${result.score}), expected ${expected}`);
    }
  }
  const aiStatus = process.env.ANTHROPIC_API_KEY
    ? 'Claude AI active (claude-haiku-4-5-20251001)'
    : 'keyword fallback — set ANTHROPIC_API_KEY=sk-ant-... to enable AI chat';
  console.log(`  Detection self-test: ${pass}/${pass + fail} passed${fail ? ' ⚠️' : ' ✅'}`);
  console.log(`  Chatbot: ${aiStatus}\n`);
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