/* ══════════════════════════════════════
   CONFIG — point to your backend server
══════════════════════════════════════ */
const API_BASE = 'http://localhost:3000';

/* ══════════════════════════════════════
   LANGUAGE PACKS
══════════════════════════════════════ */
const LANGS = {
  en: {
    headerSub: "AI-Powered Phishing Protection",
    infoBar: "Paste any link, SMS message, or scan a QR code. Our AI will instantly tell you if it's safe — in simple, clear language.",
    linkCardTitle: "Link Checker", linkCardSub: "Paste any website link below",
    smsCardTitle: "SMS / Message Checker", smsCardSub: "Copy & paste a suspicious message",
    qrCardTitle: "QR Code Scanner", qrCardSub: "Upload a QR code image to scan",
    domainCardTitle: "Domain Reputation Check", domainCardSub: "Enter just a domain name",
    linkBtnText: "Check This Link", smsBtnText: "Check This Message",
    qrBtnText: "Analyze QR Content", domainBtnText: "Check Domain",
    voiceOn: "Voice ON", voiceOff: "Voice OFF",
    spinnerText: "Analyzing… please wait",
    tryExamples: "Try examples:", historyTitle: "📋 Recent Checks",
    chatTitle: "PhishGuard AI Assistant",
    chatSub: "Ask me anything about online safety",
    noHistory: "No checks yet. Start by analyzing a link or message.",
    qrDropText: "Tap to upload a QR code photo",
  },
  hi: {
    headerSub: "AI-संचालित फ़िशिंग सुरक्षा",
    infoBar: "कोई भी लिंक, SMS, या QR कोड डालें। हमारी AI तुरंत बताएगी कि यह सुरक्षित है या नहीं।",
    linkCardTitle: "लिंक जाँचें", linkCardSub: "नीचे कोई भी वेबसाइट लिंक डालें",
    smsCardTitle: "SMS / संदेश जाँच", smsCardSub: "संदिग्ध संदेश यहाँ पेस्ट करें",
    qrCardTitle: "QR कोड स्कैनर", qrCardSub: "QR कोड छवि अपलोड करें",
    domainCardTitle: "डोमेन जाँच", domainCardSub: "केवल डोमेन नाम डालें",
    linkBtnText: "यह लिंक जाँचें", smsBtnText: "यह संदेश जाँचें",
    qrBtnText: "QR सामग्री विश्लेषण", domainBtnText: "डोमेन जाँचें",
    voiceOn: "आवाज़ ON", voiceOff: "आवाज़ OFF",
    spinnerText: "विश्लेषण हो रहा है…",
    tryExamples: "उदाहरण:", historyTitle: "📋 हालिया जाँचें",
    chatTitle: "PhishGuard AI सहायक",
    chatSub: "ऑनलाइन सुरक्षा के बारे में कुछ भी पूछें",
    noHistory: "अभी तक कोई जाँच नहीं। एक लिंक या संदेश जाँचें।",
    qrDropText: "QR कोड फ़ोटो अपलोड करने के लिए टैप करें",
  },
  ta: {
    headerSub: "AI-ஆல் இயக்கப்படும் ஃபிஷிங் பாதுகாப்பு",
    infoBar: "எந்த இணைப்பு, SMS அல்லது QR குறியீட்டையும் ஒட்டவும். எங்கள் AI உடனடியாக பாதுகாப்பை சொல்லும்.",
    linkCardTitle: "இணைப்பு சரிபார்ப்பு", linkCardSub: "கீழே இணைப்பை ஒட்டவும்",
    smsCardTitle: "SMS / செய்தி சரிபார்ப்பு", smsCardSub: "சந்தேகமான செய்தியை ஒட்டவும்",
    qrCardTitle: "QR குறியீடு ஸ்கேனர்", qrCardSub: "QR குறியீடு படத்தை பதிவேற்றவும்",
    domainCardTitle: "டொமைன் சரிபார்ப்பு", domainCardSub: "டொமைன் பெயரை உள்ளிடவும்",
    linkBtnText: "இணைப்பை சரிபார்", smsBtnText: "செய்தியை சரிபார்",
    qrBtnText: "QR உள்ளடக்கத்தை பகுப்பாய்வு", domainBtnText: "டொமைன் சரிபார்",
    voiceOn: "குரல் ON", voiceOff: "குரல் OFF",
    spinnerText: "பகுப்பாய்வு செய்கிறது…",
    tryExamples: "எடுத்துக்காட்டுகள்:", historyTitle: "📋 சமீபத்திய சரிபார்ப்புகள்",
    chatTitle: "PhishGuard AI உதவியாளர்",
    chatSub: "ஆன்லைன் பாதுகாப்பு பற்றி கேளுங்கள்",
    noHistory: "இன்னும் சரிபார்ப்பு இல்லை.",
    qrDropText: "QR குறியீடு படத்தை பதிவேற்ற தட்டவும்",
  },
  es: {
    headerSub: "Protección anti-phishing con IA",
    infoBar: "Pega cualquier enlace, SMS o código QR. Nuestra IA te dirá al instante si es seguro.",
    linkCardTitle: "Verificador de enlaces", linkCardSub: "Pega cualquier enlace web",
    smsCardTitle: "Verificador de SMS", smsCardSub: "Pega un mensaje sospechoso",
    qrCardTitle: "Escáner de QR", qrCardSub: "Sube una imagen de código QR",
    domainCardTitle: "Verificar dominio", domainCardSub: "Ingresa solo el dominio",
    linkBtnText: "Verificar enlace", smsBtnText: "Verificar mensaje",
    qrBtnText: "Analizar QR", domainBtnText: "Verificar dominio",
    voiceOn: "Voz ON", voiceOff: "Voz OFF",
    spinnerText: "Analizando…",
    tryExamples: "Ejemplos:", historyTitle: "📋 Verificaciones recientes",
    chatTitle: "Asistente IA PhishGuard",
    chatSub: "Pregúntame sobre seguridad en línea",
    noHistory: "Aún no hay verificaciones.",
    qrDropText: "Toca para subir foto de código QR",
  },
  fr: {
    headerSub: "Protection anti-phishing par IA",
    infoBar: "Collez un lien, SMS ou QR code. Notre IA vous dira instantanément s'il est sûr.",
    linkCardTitle: "Vérificateur de liens", linkCardSub: "Collez n'importe quel lien",
    smsCardTitle: "Vérificateur SMS", smsCardSub: "Collez un message suspect",
    qrCardTitle: "Scanner QR", qrCardSub: "Téléchargez une image QR",
    domainCardTitle: "Vérifier un domaine", domainCardSub: "Entrez juste le nom de domaine",
    linkBtnText: "Vérifier ce lien", smsBtnText: "Vérifier ce message",
    qrBtnText: "Analyser le QR", domainBtnText: "Vérifier le domaine",
    voiceOn: "Voix ON", voiceOff: "Voix OFF",
    spinnerText: "Analyse en cours…",
    tryExamples: "Exemples :", historyTitle: "📋 Vérifications récentes",
    chatTitle: "Assistant IA PhishGuard",
    chatSub: "Posez-moi vos questions sur la sécurité",
    noHistory: "Aucune vérification pour l'instant.",
    qrDropText: "Appuyez pour télécharger un QR code",
  },
  ar: {
    headerSub: "حماية من التصيد الاحتيالي بالذكاء الاصطناعي",
    infoBar: "الصق أي رابط أو رسالة SMS أو رمز QR. سيخبرك على الفور إذا كان آمنًا.",
    linkCardTitle: "فحص الروابط", linkCardSub: "الصق أي رابط موقع ويب",
    smsCardTitle: "فحص الرسائل", smsCardSub: "الصق رسالة مشبوهة",
    qrCardTitle: "ماسح QR", qrCardSub: "ارفع صورة رمز QR",
    domainCardTitle: "فحص النطاق", domainCardSub: "أدخل اسم النطاق فقط",
    linkBtnText: "فحص الرابط", smsBtnText: "فحص الرسالة",
    qrBtnText: "تحليل رمز QR", domainBtnText: "فحص النطاق",
    voiceOn: "الصوت مفعّل", voiceOff: "الصوت معطّل",
    spinnerText: "جارٍ التحليل…",
    tryExamples: "جرّب أمثلة:", historyTitle: "📋 الفحوصات الأخيرة",
    chatTitle: "مساعد PhishGuard الذكي",
    chatSub: "اسألني عن أي شيء يتعلق بالأمان عبر الإنترنت",
    noHistory: "لا توجد فحوصات بعد.",
    qrDropText: "اضغط لرفع صورة رمز QR",
  },
};

let currentLang = 'en';
let scanHistory = [];

function t(key) {
  return (LANGS[currentLang] || LANGS.en)[key] || LANGS.en[key] || key;
}

function applyLang() {
  const voiceToggle = document.getElementById('voiceToggle');
  const map = {
    headerSub:      'headerSub',
    infoBarText:    'infoBar',
    linkCardTitle:  'linkCardTitle',
    linkCardSub:    'linkCardSub',
    smsCardTitle:   'smsCardTitle',
    smsCardSub:     'smsCardSub',
    qrCardTitle:    'qrCardTitle',
    qrCardSub:      'qrCardSub',
    domainCardTitle:'domainCardTitle',
    domainCardSub:  'domainCardSub',
    linkBtnText:    'linkBtnText',
    smsBtnText:     'smsBtnText',
    qrBtnText:      'qrBtnText',
    domainBtnText:  'domainBtnText',
    spinnerText:    'spinnerText',
    tryExamplesLabel:'tryExamples',
    historyTitle:   'historyTitle',
    chatTitle:      'chatTitle',
    chatSubTitle:   'chatSub',
    noHistory:      'noHistory',
    qrDropText:     'qrDropText',
  };
  Object.entries(map).forEach(([id, key]) => {
    const el = document.getElementById(id);
    if (el) el.textContent = t(key);
  });
  const voiceLabel = document.getElementById('voiceLabel');
  if (voiceLabel) voiceLabel.textContent = voiceToggle.checked ? t('voiceOn') : t('voiceOff');
  document.documentElement.lang = currentLang;
  document.body.dir = currentLang === 'ar' ? 'rtl' : 'ltr';
}

function changeLang(lang) {
  currentLang = lang;
  applyLang();
}

/* ══════════════════════════════════════
   VOICE
══════════════════════════════════════ */
function speak(text) {
  const voiceToggle = document.getElementById('voiceToggle');
  if (!voiceToggle.checked) return;
  if (!('speechSynthesis' in window)) return;
  window.speechSynthesis.cancel();
  const utt = new SpeechSynthesisUtterance(text);
  utt.lang = { en:'en-US', hi:'hi-IN', ta:'ta-IN', es:'es-ES', fr:'fr-FR', ar:'ar-SA' }[currentLang] || 'en-US';
  utt.rate = 0.92;
  window.speechSynthesis.speak(utt);
}

/* ══════════════════════════════════════
   BACKEND API CALLS
══════════════════════════════════════ */

// Map language dropdown value to backend lang key
function getLangKey() {
  const map = { en:'en', hi:'hi', ta:'ta', es:'en', fr:'en', ar:'ar' };
  return map[currentLang] || 'en';
}

async function callBackend(endpoint, body) {
  try {
    const res = await fetch(`${API_BASE}${endpoint}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    
    if (!res.ok) {
      throw new Error(`Server error: ${res.status}`);
    }
    
    const data = await res.json();
    return data;
  } catch (error) {
    console.error('Backend call failed:', error);
    throw error;
  }
}

/* ══════════════════════════════════════
   CONVERT BACKEND RESULT → DISPLAY FORMAT
   Backend returns: { status, score, reasons, message }
   Display needs:   { risk, emoji, title, explanation, tips, voice_alert }
══════════════════════════════════════ */
function backendToDisplay(result) {
  const riskMap = { SAFE: 'SAFE', SUSPICIOUS: 'SUSPICIOUS', DANGEROUS: 'DANGEROUS' };
  const emojiMap = { SAFE: '✅', SUSPICIOUS: '⚠️', DANGEROUS: '🚨' };
  const titleMap = {
    SAFE: 'Looks Safe',
    SUSPICIOUS: 'Looks Suspicious',
    DANGEROUS: 'Danger — Likely Phishing'
  };

  return {
    risk: riskMap[result.status] || 'SUSPICIOUS',
    emoji: emojiMap[result.status] || '⚠️',
    title: titleMap[result.status] || result.status,
    explanation: result.message || 'Analysis complete.',
    tips: result.reasons && result.reasons.length > 0
      ? result.reasons.slice(0, 3)
      : ['Always double-check links before clicking.', 'Never share your OTP or PIN.', 'When in doubt, contact your bank directly.'],
    voice_alert: result.message || ''
  };
}

/* ══════════════════════════════════════
   SHOW RESULT
══════════════════════════════════════ */
function showResult(data, inputPreview, type) {
  const panel = document.getElementById('resultPanel');
  panel.classList.add('show');

  const riskMap = { SAFE:'safe', SUSPICIOUS:'warn', DANGEROUS:'danger' };
  const state = riskMap[data.risk] || 'safe';

  document.getElementById('resultBadge').textContent = data.emoji;
  document.getElementById('resultLabel').textContent = data.title;
  document.getElementById('resultSub').textContent =
    { SAFE:'✅ No threats detected', SUSPICIOUS:'⚠️ Proceed with caution', DANGEROUS:'🚨 Do not proceed!' }[data.risk];
  document.getElementById('resultExplain').textContent = data.explanation;

  const tipsEl = document.getElementById('resultTips');
  tipsEl.innerHTML = (data.tips || []).map(tip =>
    `<div class="tip-item"><span class="tip-icon">${state==='safe'?'✅':state==='warn'?'⚠️':'🚫'}</span>${escHtml(tip)}</div>`
  ).join('');

  document.getElementById('mainGrid').className = 'main state-' + state;
  panel.scrollIntoView({ behavior: 'smooth', block: 'center' });

  if (data.voice_alert) speak(data.voice_alert);

  addHistory(inputPreview, data.risk, type, state);
}

/* ══════════════════════════════════════
   ANALYZE FUNCTIONS — now call backend
══════════════════════════════════════ */
async function runAnalysis(endpoint, body, inputPreview, type) {
  showSpinner(true);
  disableButtons(true);
  try {
    const result = await callBackend(endpoint, body);
    const display = backendToDisplay(result);
    showResult(display, inputPreview, type);
  } catch (e) {
    console.error('Analysis error:', e);
    // Show a more specific error message based on the error type
    let errorMsg = 'Analysis failed. ';
    if (e.message === 'Failed to fetch') {
      errorMsg += 'Cannot connect to server. Make sure the server is running on http://localhost:3000\n\nRun: node server.js';
    } else if (e.message.includes('Server error')) {
      errorMsg += `Server returned error: ${e.message}`;
    } else {
      errorMsg += 'Please check if the backend server is running properly.';
    }
    alert(errorMsg);
  } finally {
    showSpinner(false);
    disableButtons(false);
  }
}

function analyzeLink() {
  const v = document.getElementById('linkInput').value.trim();
  if (!v) return alert('Please enter a link to check.');
  runAnalysis('/api/check-link', { url: v, lang: getLangKey() }, v, 'URL/Link');
}

function analyzeSMS() {
  const v = document.getElementById('smsInput').value.trim();
  if (!v) return alert('Please enter a message to check.');
  runAnalysis('/api/check-sms', { text: v, lang: getLangKey() }, v.slice(0, 50) + '…', 'SMS');
}

function analyzeDomain() {
  const v = document.getElementById('domainInput').value.trim();
  if (!v) return alert('Please enter a domain to check.');
  // Domain check reuses the link endpoint — prepend https:// if missing
  const url = v.startsWith('http') ? v : 'https://' + v;
  runAnalysis('/api/check-link', { url, lang: getLangKey() }, v, 'Domain');
}

function analyzeQR() {
  const v = document.getElementById('qrDecoded').value.trim();
  if (!v) return alert('Please scan or upload a QR code first.');
  runAnalysis('/api/check-qr', { url: v, lang: getLangKey() }, v.slice(0, 50), 'QR Code');
}

/* ══════════════════════════════════════
   QR HANDLING (jsQR)
══════════════════════════════════════ */
function handleQR(event) {
  const file = event.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = function(e) {
    const img = new Image();
    img.onload = function() {
      const canvas = document.createElement('canvas');
      canvas.width = img.width; canvas.height = img.height;
      const ctx = canvas.getContext('2d');
      ctx.drawImage(img, 0, 0);
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const code = jsQR(imageData.data, imageData.width, imageData.height);
      const preview = document.getElementById('qrPreview');
      preview.src = e.target.result;
      preview.style.display = 'block';
      const decoded = document.getElementById('qrDecoded');
      const btn = document.getElementById('qrBtn');
      if (code) {
        decoded.value = code.data;
        decoded.style.display = 'block';
        btn.style.display = 'flex';
      } else {
        decoded.value = '';
        decoded.placeholder = 'Could not decode QR. Try a clearer image.';
        decoded.style.display = 'block';
        btn.style.display = 'none';
      }
    };
    img.src = e.target.result;
  };
  reader.readAsDataURL(file);
}

// Drag & drop
document.addEventListener('DOMContentLoaded', () => {
  const qrDrop = document.getElementById('qrDrop');
  if (qrDrop) {
    qrDrop.addEventListener('dragover', e => { e.preventDefault(); qrDrop.classList.add('drag-over'); });
    qrDrop.addEventListener('dragleave', () => qrDrop.classList.remove('drag-over'));
    qrDrop.addEventListener('drop', e => {
      e.preventDefault(); qrDrop.classList.remove('drag-over');
      const file = e.dataTransfer.files[0];
      if (file) handleQR({ target: { files: [file] } });
    });
  }

  // Voice toggle label
  const voiceToggle = document.getElementById('voiceToggle');
  if (voiceToggle) {
    voiceToggle.addEventListener('change', () => {
      document.getElementById('voiceLabel').textContent = voiceToggle.checked ? t('voiceOn') : t('voiceOff');
    });
  }

  applyLang();
  renderHistory();
});

/* ══════════════════════════════════════
   UTILITIES
══════════════════════════════════════ */
function showSpinner(show) {
  const spinner = document.getElementById('spinnerWrap');
  if (spinner) spinner.classList.toggle('show', show);
}

function disableButtons(d) {
  ['linkBtn','smsBtn','qrBtn','domainBtn','chatSend'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.disabled = d;
  });
}

function setExample(field, val) {
  if (field === 'link') {
    const linkInput = document.getElementById('linkInput');
    if (linkInput) {
      linkInput.value = val;
      linkInput.focus();
    }
  } else if (field === 'sms') {
    const smsInput = document.getElementById('smsInput');
    if (smsInput) {
      smsInput.value = val;
      smsInput.focus();
    }
  }
}

function escHtml(t) {
  return String(t).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

/* ══════════════════════════════════════
   HISTORY
══════════════════════════════════════ */
function addHistory(text, risk, type, state) {
  scanHistory.unshift({ text, risk, type, state, time: new Date().toLocaleTimeString() });
  renderHistory();
}

function renderHistory() {
  const list = document.getElementById('historyList');
  const noEl = document.getElementById('noHistory');
  if (scanHistory.length === 0) {
    if (noEl) noEl.style.display = 'block';
    if (list) {
      list.innerHTML = '';
      if (noEl) list.appendChild(noEl);
    }
    return;
  }
  if (noEl) noEl.style.display = 'none';
  if (list) {
    list.innerHTML = scanHistory.slice(0, 10).map(item => `
      <div class="history-item">
        <div class="history-dot dot-${item.state}"></div>
        <div class="history-text">
          <div class="history-url">${escHtml(item.text)}</div>
          <div class="history-meta">${item.type} · ${item.time}</div>
        </div>
        <div class="history-badge badge-${item.state}">${item.risk}</div>
      </div>
    `).join('');
  }
}

function clearHistory() {
  scanHistory = [];
  renderHistory();
  const resultPanel = document.getElementById('resultPanel');
  if (resultPanel) resultPanel.classList.remove('show');
  const mainGrid = document.getElementById('mainGrid');
  if (mainGrid) mainGrid.className = 'main';
}

/* ══════════════════════════════════════
   CHATBOT — calls backend /api/chatbot
══════════════════════════════════════ */
async function sendChat() {
  const input = document.getElementById('chatInput');
  const msg = input.value.trim();
  if (!msg) return;
  input.value = '';
  addChatMsg(msg, 'user');
  const typingId = addTyping();
  const sendBtn = document.getElementById('chatSend');
  if (sendBtn) sendBtn.disabled = true;

  try {
    const data = await callBackend('/api/chatbot', { message: msg });
    const reply = data.reply || 'I am sorry, I could not process that.';
    removeTyping(typingId);
    addChatMsg(reply, 'bot');
    const voiceToggle = document.getElementById('voiceToggle');
    if (voiceToggle && voiceToggle.checked && reply.length < 200) speak(reply);
  } catch (error) {
    console.error('Chat error:', error);
    removeTyping(typingId);
    let errorMsg = 'Sorry, I could not connect to the server. ';
    if (error.message === 'Failed to fetch') {
      errorMsg += 'Make sure the server is running on http://localhost:3000';
    } else {
      errorMsg += 'Please check if the backend server is running properly.';
    }
    addChatMsg(errorMsg, 'bot');
  } finally {
    if (sendBtn) sendBtn.disabled = false;
  }
}

function addChatMsg(text, who) {
  const wrap = document.getElementById('chatMessages');
  if (!wrap) return null;
  const div = document.createElement('div');
  div.className = 'msg msg-' + who;
  if (who === 'bot') {
    div.innerHTML = `<span class="bot-tag">PhishGuard AI</span>${escHtml(text).replace(/\n/g,'<br>')}`;
  } else {
    div.textContent = text;
  }
  wrap.appendChild(div);
  wrap.scrollTop = wrap.scrollHeight;
  return div;
}

let typingCounter = 0;
function addTyping() {
  const id = 'typing-' + (++typingCounter);
  const wrap = document.getElementById('chatMessages');
  if (!wrap) return id;
  const div = document.createElement('div');
  div.className = 'msg msg-bot';
  div.id = id;
  div.innerHTML = `<span class="bot-tag">PhishGuard AI</span><div class="typing-dots"><span></span><span></span><span></span></div>`;
  wrap.appendChild(div);
  wrap.scrollTop = wrap.scrollHeight;
  return id;
}

function removeTyping(id) {
  const el = document.getElementById(id);
  if (el) el.remove();
}

function askChip(question) {
  const chatInput = document.getElementById('chatInput');
  if (chatInput) chatInput.value = question;
  sendChat();
}