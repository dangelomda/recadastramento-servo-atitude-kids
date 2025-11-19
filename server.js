require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const pdfParse = require('pdf-parse');
const dayjs = require('dayjs');
const customParseFormat = require('dayjs/plugin/customParseFormat');
dayjs.extend(customParseFormat);

const rateLimit = require('express-rate-limit');
const { cpf: cpfValidator } = require('cpf-cnpj-validator');
const { Pool } = require('pg');
const { createClient } = require('@supabase/supabase-js');
const nodemailer = require('nodemailer');
const path = require('path');
const webpush = require('web-push');

// =====================
// Config & Branding
// =====================
const ORG = process.env.ORG_NOME || 'Recadastramento Servo Atitude Kids';
const BRAND = {
    primary: process.env.BRAND_PRIMARY || '#4f46e5',
    accent: process.env.BRAND_ACCENT || '#22c55e',
    logo: process.env.BRAND_LOGO_PATH || '/public/logo.svg',
};

// Sessão/atividade
const MAX_IDLE_MS = 10 * 60 * 1000; // 10 minutos
const TOKEN_TTL_MS = 12 * 60 * 60 * 1000;

// =====================
// App base
// =====================
const app = express();


app.use('/public', express.static(path.join(__dirname, 'public'), {
  etag: false, lastModified: false, maxAge: 0
}));
app.use('/favicon.svg', express.static(path.join(__dirname, 'public', 'favicon.svg')));

app.get('/service-worker.js', (req, res) => {
  res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private, max-age=0');
  res.sendFile(path.resolve(__dirname, 'public', 'service-worker.js'));
});


// Infra
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false,
    },
});

// Mail
let transporter = null;
if (process.env.SMTP_HOST) {
    transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: Number(process.env.SMTP_PORT || 587),
        secure: String(process.env.SMTP_SECURE || 'false') === 'true',
        auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
    });
}

// Configuração do Web Push com as chaves VAPID
if (process.env.VAPID_PUBLIC_KEY && process.env.VAPID_PRIVATE_KEY) {
    webpush.setVapidDetails(
        process.env.VAPID_SUBJECT,
        process.env.VAPID_PUBLIC_KEY,
        process.env.VAPID_PRIVATE_KEY
    );
    console.log('✅ Web Push configurado.');
} else {
    console.warn('⚠️  Chaves VAPID não configuradas. Notificações Push estão desabilitadas.');
}

// Middlewares
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 500 }));
app.set('trust proxy', 1);

// Upload
const upload = multer({ limits: { fileSize: 2 * 1024 * 1024 } });

// =====================
// Helpers - Formatação, Email, Token & Sessão
// =====================

function formatCPF(cpf) {
    const cleaned = (cpf || '').toString().replace(/\D/g, '');
    if (cleaned.length !== 11) {
        return cpf || '-';
    }
    return cleaned.replace(/(\d{3})(\d{3})(\d{3})(\d{2})/, '$1.$2.$3-$4');
}

function formatPhone(phone) {
    const cleaned = (phone || '').toString().replace(/\D/g, '');
    if (cleaned.length === 11) {
        return cleaned.replace(/(\d{2})(\d{5})(\d{4})/, '($1) $2-$3');
    }
    if (cleaned.length === 10) {
        return cleaned.replace(/(\d{2})(\d{4})(\d{4})/, '($1) $2-$3');
    }
    return phone || '-';
}

async function sendEmail(to, subject, html) {
    if (!transporter) {
        console.log(`Email não enviado para ${to} (transporter não configurado). Assunto: ${subject}`);
        return;
    }
    try {
        await transporter.sendMail({
            from: process.env.MAIL_FROM,
            to,
            subject,
            html
        });
        console.log(`Email enviado para ${to}`);
    } catch (error) {
        console.error(`Falha ao enviar e-mail para ${to}:`, error);
    }
}

async function sendPushNotification(userId, payload) {
    if (!process.env.VAPID_PUBLIC_KEY) return;
    try {
        const { rows: subscriptions } = await pool.query(
            'SELECT id, subscription FROM push_subscriptions WHERE user_id = $1',
            [userId]
        );
        if (subscriptions.length === 0) return;

        console.log(`Enviando push para ${subscriptions.length} dispositivo(s) do usuário ${userId}`);
        const notificationPayload = JSON.stringify(payload);

        const promises = subscriptions.map(s =>
            webpush.sendNotification(s.subscription, notificationPayload)
            .catch(error => {
                if (error.statusCode === 410) {
                    console.log(`Inscrição ${s.id} expirou. Removendo do banco.`);
                    return pool.query('DELETE FROM push_subscriptions WHERE id = $1', [s.id]);
                } else {
                    console.error(`Erro ao enviar push para inscrição ${s.id}:`, error.body);
                }
            })
        );
        await Promise.all(promises);
    } catch (error) {
        console.error(`Erro ao buscar inscrições para o usuário ${userId}:`, error);
    }
}

function nowMs() { return Date.now(); }

function signToken(payload, secretEnv = 'SESSION_SECRET') {
    const secret = process.env[secretEnv] || 'dev-secret';
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
    const iat = nowMs();
    const exp = iat + TOKEN_TTL_MS;
    const full = { ...payload, iat, exp, lastActivity: iat };
    const body = Buffer.from(JSON.stringify(full)).toString('base64url');
    const sig = crypto.createHmac('sha256', secret).update(`${header}.${body}`).digest('base64url');
    return `${header}.${body}.${sig}`;
}

function verifyToken(token, secretEnv = 'SESSION_SECRET') {
    const secret = process.env[secretEnv] || 'dev-secret';
    const [h, b, s] = (token || '').split('.');
    if (!h || !b || !s) return null;
    const sig = crypto.createHmac('sha256', secret).update(`${h}.${b}`).digest('base64url');
    if (sig !== s) return null;
    try {
        const data = JSON.parse(Buffer.from(b, 'base64url').toString());
        if (!data.exp || data.exp < nowMs()) return null;
        return data;
    } catch {
        return null;
    }
}

function refreshActivityCookie(kind, data) {
    const updated = { ...data, lastActivity: nowMs() };
    const token = signToken(updated);
    return { name: kind === 'admin' ? 'admin_session' : 'vol_session', token };
}

function isIdle(data) {
    if (!data || !data.lastActivity) return true;
    return (nowMs() - data.lastActivity) > MAX_IDLE_MS;
}

function clearAllSessions(res) {
    res.clearCookie('vol_session');
    res.clearCookie('admin_session');
}

function setNoCacheHeaders(req, res, next) {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    next();
}

function requireAdmin(req, res, next) {
    const t = req.cookies['admin_session'];
    const data = verifyToken(t);
    if (!data || !data.role || !data.role.startsWith('admin')) {
        return res.redirect('/admin/login');
    }
    if (isIdle(data)) {
        clearAllSessions(res);
        return res.redirect('/admin/login?timeout=1');
    }
    const { name, token } = refreshActivityCookie('admin', data);
    res.cookie(name, token, { httpOnly: true, sameSite: 'lax', secure: true });
    req.admin = data;
    return next();
}

function requireSuper(req, res, next) {
    const t = req.cookies['admin_session'];
    const d = verifyToken(t);
    if (!d || d.role !== 'admin:super') {
        return res.status(403).send('Somente super admin.');
    }
    if (isIdle(d)) {
        clearAllSessions(res);
        return res.redirect('/admin/login?timeout=1');
    }
    const { name, token } = refreshActivityCookie('admin', d);
    res.cookie(name, token, { httpOnly: true, sameSite: 'lax', secure: true });
    req.admin = d;
    return next();
}

function requireVolunteer(req, res, next) {
    const t = req.cookies['vol_session'];
    const data = verifyToken(t);
    if (!data || !data.volunteer_id) {
        return res.redirect('/login');
    }
    if (isIdle(data)) {
        clearAllSessions(res);
        return res.redirect('/login');
    }
    const { name, token } = refreshActivityCookie('vol', data);
    res.cookie(name, token, { httpOnly: true, sameSite: 'lax', secure: true });
    req.vol = data;
    return next();
}

function badge(status, cacResult) {
    if (status === 'inapto') return '🔴 Inapto';
    if (status === 'atencao') return '🟡 Atenção';
    if (status === 'apto' && cacResult === 'nada_consta') return '✅ Apto';
    if (status === 'apto') return '⚠️ Apto (Revisar)';
    return '⚪ Em revisão';
}

// =====================
// PDF parsing
// =====================
async function extractFromPdf(pdfBuffer) {
    const pdfData = await pdfParse(pdfBuffer);
    const text = (pdfData.text || '').toUpperCase().replace(/\s+/g, ' ');
    const numMatch = text.match(/N[º°:]\s*(\d{6,})/) || text.match(/CRIMINAIS N° (\d+)/);
    const datePatterns = [
        /ASSINADO ELETRONICAMENTE POR.*EM (\d{2}\/\d{2}\/\d{4})/,
        /FOI EXPEDIDA EM (\d{2}\/\d{2}\/\d{4})/,
        /EXPEDIDA EM\s*(\d{2}\/\d{2}\/\d{4})/,
        /EMITIDA EM\s*(\d{2}\/\d{2}\/\d{4})/,
        /DATA DE EXPEDI[ÇC][AÃ]O\s*[:\-]?\s*(\d{2}\/\d{2}\/\d{4})/
    ];
    let issued_at = null;
    for (const regex of datePatterns) {
        const match = text.match(regex);
        if (match && match[1]) {
            const parsedDate = dayjs(match[1], 'DD/MM/YYYY');
            if (parsedDate.isValid()) {
                issued_at = parsedDate;
                break;
            }
        }
    }
    if ((!issued_at || !issued_at.isValid()) && !text.includes('EXPEDIDA EM')) {
        const anyDate = text.match(/(\d{2}\/\d{2}\/\d{4})/);
        if (anyDate && anyDate[1]) {
            if (!text.includes(`NASCIDO(A) AOS ${anyDate[1]}`)) {
                const parsedDate = dayjs(anyDate[1], 'DD/MM/YYYY');
                if (parsedDate.isValid()) {
                    issued_at = parsedDate;
                }
            }
        }
    }
    const cpfMatch = text.match(/CPF\s*(?:N[º°:])?\s*(\d{3}\.\d{3}\.\d{3}-\d{2})/);
    const pdf_cpf = cpfMatch ? cpfMatch[1].replace(/\D/g, '') : null;
    const cert_number = numMatch ? numMatch[1] : null;
    const expires_at = (issued_at && issued_at.isValid()) ? issued_at.add(6, 'month') : null;
    let cac_result = 'desconhecido';
    if (text.includes('NÃO CONSTA') || text.includes('NADA CONSTA')) {
        cac_result = 'nada_consta';
    }

    // ##################################################################
    // ## INÍCIO DA ADIÇÃO: Extrair Data de Nascimento
    // ##################################################################
    let data_nascimento = null;
    const nascMatch = text.match(/NASCIDO\(A\) AOS (\d{2}\/\d{2}\/\d{4})/);
    if (nascMatch && nascMatch[1]) {
        const parsedDate = dayjs(nascMatch[1], 'DD/MM/YYYY');
        if (parsedDate.isValid()) {
            data_nascimento = parsedDate;
        }
    }
    // ##################################################################
    // ## FIM DA ADIÇÃO
    // ##################################################################

    return { cert_number, issued_at, expires_at, cac_result, pdf_cpf, data_nascimento }; // <-- data_nascimento adicionada ao retorno
}

// =====================
// Page templates
// =====================
const baseHead = (title) => `
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>${title}</title>
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<script src="https://cdn.tailwindcss.com"></script>
<style>
  :root{ --brand:${BRAND.primary}; --accent:${BRAND.accent}; }
  .btn-brand{ background: var(--brand); color:#fff; }
  .btn-brand:hover{ filter: brightness(0.95); }
  .link-brand{ color: var(--brand); }
  .btn-brand:disabled {
    background-color: #9ca3af;
    cursor: not-allowed;
    filter: none;
  }
</style>
`;

const antiBFCacheScript = `
  window.addEventListener('pageshow', function(e){
    if (e.persisted) {
      window.location.reload();
    }
  });
`;

function activityHeartbeatScript(kind) {
    return `
  (function(){
    const SESSION_KIND='${kind}';
    const PING_URL='/auth/ping';
    let lastSent=0;
    let pending=false;
    const DEBOUNCE=3000;
    function ping(){
      const now=Date.now();
      if (pending || (now-lastSent)<DEBOUNCE) return;
      pending=true;
      fetch(PING_URL, {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ kind: SESSION_KIND })
      }).finally(()=>{ pending=false; lastSent=Date.now(); });
    }
    ['click','keydown','mousemove','scroll','touchstart','visibilitychange'].forEach(evt => {
      window.addEventListener(evt, () => {
        if (document.visibilityState !== 'hidden') ping();
      }, {passive:true});
    });
    ping();
  })();
  `;
}

const page = (title, bodyHtml, extraScripts = '') => `<!doctype html>
<html lang="pt-BR">
<head>
${baseHead(title)}
</head>
<body class="bg-slate-50 text-slate-800">
<header class="bg-white border-b sticky top-0 z-10">
  <div class="max-w-7xl mx-auto px-4 py-4 flex items-center justify-between">
    <div class="flex items-center gap-3">
      <img src="${BRAND.logo}" alt="logo" class="h-8 w-auto" onerror="this.src='/public/logo.svg'">
      <div class="text-lg font-semibold">${ORG}</div>
    </div>
    <nav class="text-sm">
      <button id="menu-btn" class="md:hidden p-2 rounded-md focus:outline-none focus:ring-2 focus:ring-slate-400">
        <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16m-7 6h7" />
        </svg>
      </button>
      
      <div id="menu-links-desktop" class="hidden md:flex md:items-center md:gap-4">
        <a href="/" class="hover:text-brand">Início</a>
        <a href="/cadastro" class="hover:text-brand">Cadastro</a>
        <a href="/login" class="hover:text-brand">Login</a>
        <a href="/admin/login" class="ml-2 pl-4 border-l border-slate-200 hover:text-brand">Admin</a>
      </div>
    </nav>
  </div>
  <div id="menu-links-mobile" class="hidden md:hidden bg-white border-t">
      <a href="/" class="block text-center py-3 text-sm hover:bg-slate-100">Início</a>
      <a href="/cadastro" class="block text-center py-3 text-sm hover:bg-slate-100">Cadastro</a>
      <a href="/login" class="block text-center py-3 text-sm hover:bg-slate-100">Login</a>
      <a href="/admin/login" class="block text-center py-3 text-sm border-t hover:bg-slate-100">Admin</a>
  </div>
</header>
<main class="max-w-7xl mx-auto px-4 py-8">
${bodyHtml}
</main>
<footer class="text-center text-xs text-slate-500 py-8">© ${new Date().getFullYear()} ${ORG}</footer>

<script>
  ${antiBFCacheScript}
  const menuBtn = document.getElementById('menu-btn');
  const mobileMenu = document.getElementById('menu-links-mobile');
  if (menuBtn && mobileMenu) {
    menuBtn.addEventListener('click', () => {
      mobileMenu.classList.toggle('hidden');
    });
  }

  const forms = document.querySelectorAll('form');
  forms.forEach(form => {
    form.addEventListener('submit', (e) => {
      const submitButton = form.querySelector('button[type="submit"]');
      if (submitButton) {
        submitButton.disabled = true;
        submitButton.textContent = 'Processando...';
      }
    });
  });

  const fileInput = document.querySelector('input[type="file"][name="cac_pdf"]');
  if (fileInput) {
    fileInput.addEventListener('change', function(event) {
      const file = event.target.files[0];
      if (file) {
        if (file.size > 2 * 1024 * 1024) {
          alert('Erro: O arquivo é muito grande! O tamanho máximo permitido é 2MB.');
          event.target.value = ''; 
        }
      }
    });
  }

  document.querySelectorAll('.password-toggle-container').forEach(container => {
    const input = container.querySelector('input[type="password"], input[type="text"]');
    const toggle = container.querySelector('.password-toggle-icon');
    const eyeIcon = toggle.querySelector('.eye-icon');
    const eyeSlashIcon = toggle.querySelector('.eye-slash-icon');

    toggle.addEventListener('click', () => {
      if (input.type === 'password') {
        input.type = 'text';
        eyeIcon.classList.add('hidden');
        eyeSlashIcon.classList.remove('hidden');
      } else {
        input.type = 'password';
        eyeIcon.classList.remove('hidden');
        eyeSlashIcon.classList.add('hidden');
      }
    });
  });

  ${activityHeartbeatScript('public')}
</script>
${extraScripts} 
</body>
</html>`;

const adminPage = (title, bodyHtml, admin = null) => {
    const navLinksDesktop = admin && admin.email
      ? `
        <div class="flex items-center gap-4">
          <span class="text-sm text-slate-600">Logado como: <strong>${admin.email}</strong></span>
          <a href="/admin/logout" class="link-brand underline text-sm">Sair</a>
        </div>
      `
      : `
        <a href="/" class="hover:text-brand">Início</a>
        <a href="/cadastro" class="hover:text-brand">Cadastro</a>
        <a href="/login" class="hover:text-brand">Login</a>
        <a href="/admin/login" class="ml-2 pl-4 border-l border-slate-200 hover:text-brand">Admin</a>
      `;

    const navLinksMobile = admin && admin.email
      ? `
        <div class="text-center py-3 text-sm text-slate-600">Logado como: <strong>${admin.email}</strong></div>
        <a href="/admin/logout" class="block text-center py-3 text-sm border-t hover:bg-slate-100 link-brand">Sair</a>
      `
      : `
        <a href="/" class="block text-center py-3 text-sm hover:bg-slate-100">Início</a>
        <a href="/cadastro" class="block text-center py-3 text-sm hover:bg-slate-100">Cadastro</a>
        <a href="/login" class="block text-center py-3 text-sm hover:bg-slate-100">Login</a>
        <a href="/admin/login" class="block text-center py-3 text-sm border-t hover:bg-slate-100">Admin</a>
      `;

    // SCRIPT DE LOGOUT POR INATIVIDADE
    const idleLogoutScript = admin && admin.email ? `
    <script>
    (() => {
      const IDLE_MS = ${MAX_IDLE_MS};
      const PING_MS = 30 * 1000;      // Checa a cada 30 segundos
      const LOGOUT_URL = '/admin/logout?timeout=1';
      const KEY = 'admin_last_activity_ts';
      
      const markActivity = () => localStorage.setItem(KEY, String(Date.now()));

      ['mousemove','mousedown','keydown','scroll','touchstart','focus'].forEach(evt => window.addEventListener(evt, markActivity, {passive:true}));
      document.addEventListener('visibilitychange', () => {
        if (!document.hidden) markActivity();
      });

      if (!localStorage.getItem(KEY)) markActivity();

      setInterval(() => {
        const last = Number(localStorage.getItem(KEY) || 0);
        if (Date.now() - last > IDLE_MS) {
          localStorage.removeItem(KEY);
          location.replace(LOGOUT_URL);
        }
      }, PING_MS);
    })();
    </script>
    ` : '';

    // ##################################################################
    // ## INÍCIO DA ADIÇÃO: HTML do Modal de Validação
    // ##################################################################
    const validationModalHtml = `
    <div id="validar-modal" class="fixed inset-0 bg-gray-800 bg-opacity-75 flex items-center justify-center p-4 hidden z-50">
      <div class="bg-white rounded-lg p-6 max-w-lg w-full">
        <h2 class="text-xl font-semibold mb-4">Validar Certidão na PF</h2>
        <div class="space-y-3">
          <div>
            <label class="block text-sm font-medium text-gray-700">Servo</label>
            <div id="modal-servo-nome" class="mt-1 p-2 border rounded-md bg-gray-50"></div>
          </div>
          <div>
            <label class="block text-sm font-medium text-gray-700">Data de Nascimento (Copie e Cole)</label>
            <div class="mt-1 flex rounded-md shadow-sm">
              <input type="text" id="modal-data-nasc" readonly class="flex-1 block w-full rounded-none rounded-l-md p-2 border-gray-300 bg-gray-50">
              <button type="button" id="modal-copy-btn" class="relative -ml-px inline-flex items-center space-x-2 rounded-r-md border border-gray-300 bg-gray-100 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-200">
                <span>Copiar</span>
              </button>
            </div>
          </div>
          <div class="pt-4 border-t mt-4 flex flex-col sm:flex-row gap-3">
            <a href="#" id="modal-pf-link" target="_blank" class="btn-brand w-full text-center block px-5 py-3 rounded-lg">1. Abrir site da PF</a>
            <button type="button" id="modal-close-btn" class="w-full text-center px-5 py-3 border rounded text-gray-600 hover:bg-gray-100">2. Fechar</button>
          </div>
        </div>
      </div>
    </div>
    `;
    // ##################################################################
    // ## FIM DA ADIÇÃO: HTML do Modal de Validação
    // ##################################################################


    return `<!doctype html>
    <html lang="pt-BR">
    <head>
    ${baseHead(title)}
    </head>
    <body class="bg-slate-50 text-slate-800">
    <header class="bg-white border-b sticky top-0 z-10">
      <div class="max-w-7xl mx-auto px-4 py-4 flex items-center justify-between">
        <div class="flex items-center gap-3">
          <img src="${BRAND.logo}" alt="logo" class="h-8 w-auto" onerror="this.src='/public/logo.svg'">
          <div class="text-lg font-semibold">${ORG}</div>
        </div>
        <nav class="text-sm">
            <button id="menu-btn" class="md:hidden p-2 rounded-md focus:outline-none focus:ring-2 focus:ring-slate-400">
              <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16m-7 6h7" />
              </svg>
            </button>
            
            <div id="menu-links-desktop" class="hidden md:flex md:items-center md:gap-4">
              ${navLinksDesktop}
            </div>
        </nav>
      </div>
      <div id="menu-links-mobile" class="hidden md:hidden bg-white border-t">
          ${navLinksMobile}
      </div>
    </header>
    <main class="w-full px-4 sm:px-6 lg:px-8 py-8">
    ${bodyHtml}
    </main>
    
    ${validationModalHtml}

    <footer class="text-center text-xs text-slate-500 py-8">© ${new Date().getFullYear()} ${ORG}</footer>

    <script>
      ${antiBFCacheScript}
      const menuBtn = document.getElementById('menu-btn');
      const mobileMenu = document.getElementById('menu-links-mobile');
      if(menuBtn && mobileMenu) {
        menuBtn.addEventListener('click', () => {
          mobileMenu.classList.toggle('hidden');
        });
      }

      document.querySelectorAll('.password-toggle-container').forEach(container => {
        const input = container.querySelector('input[type="password"], input[type="text"]');
        const toggle = container.querySelector('.password-toggle-icon');
        const eyeIcon = toggle.querySelector('.eye-icon');
        const eyeSlashIcon = toggle.querySelector('.eye-slash-icon');

        toggle.addEventListener('click', () => {
          if (input.type === 'password') {
            input.type = 'text';
            eyeIcon.classList.add('hidden');
            eyeSlashIcon.classList.remove('hidden');
          } else {
            input.type = 'password';
            eyeIcon.classList.remove('hidden');
            eyeSlashIcon.classList.add('hidden');
          }
        });
      });

      ${activityHeartbeatScript('admin')}

      // ##################################################################
      // ## INÍCIO DA ADIÇÃO: Script do Modal de Validação
      // ##################################################################
      (() => {
        const modal = document.getElementById('validar-modal');
        if (!modal) return;

        const modalNome = document.getElementById('modal-servo-nome');
        const modalDataInput = document.getElementById('modal-data-nasc');
        const modalCopyBtn = document.getElementById('modal-copy-btn');
        const modalPfLink = document.getElementById('modal-pf-link');
        const modalCloseBtn = document.getElementById('modal-close-btn');
        
        const pfUrlBase = 'https://servicos.pf.gov.br/epol-sinic-publico/validar-cac/';

        document.body.addEventListener('click', (e) => {
          // Delegação de evento para os botões de validação
          if (e.target && e.target.matches('.btn-validar-pf')) {
            e.preventDefault();
            
            const btn = e.target;
            const nome = btn.getAttribute('data-nome');
            const cert = btn.getAttribute('data-cert');
            const nasc = btn.getAttribute('data-nasc');

            if (modalNome) modalNome.textContent = nome || 'N/A';
            if (modalDataInput) modalDataInput.value = nasc || 'NÃO ENCONTRADA';
            
            if (modalDataInput && !nasc) {
              modalDataInput.classList.add('text-red-600', 'font-bold');
            } else if (modalDataInput) {
              modalDataInput.classList.remove('text-red-600', 'font-bold');
            }
            
            // ##################################################
            // ## AQUI ESTÁ A CORREÇÃO DO SYNTAXERROR
            // ##################################################
            if (modalPfLink) modalPfLink.href = pfUrlBase + (cert || '');
            
            if (modalCopyBtn) modalCopyBtn.textContent = 'Copiar';

            modal.classList.remove('hidden');
          }
        });

        if (modalCloseBtn) {
          modalCloseBtn.addEventListener('click', () => {
            modal.classList.add('hidden');
          });
        }
        
        // Fechar clicando fora
        modal.addEventListener('click', (e) => {
          if (e.target === modal) {
            modal.classList.add('hidden');
          }
        });

        if (modalCopyBtn && modalDataInput) {
          modalCopyBtn.addEventListener('click', () => {
            navigator.clipboard.writeText(modalDataInput.value).then(() => {
              modalCopyBtn.textContent = 'Copiado!';
              setTimeout(() => { modalCopyBtn.textContent = 'Copiar'; }, 2000);
            }).catch(err => {
              console.error('Erro ao copiar:', err);
              // Fallback para seleção manual
              modalDataInput.select();
              alert('Não foi possível copiar automaticamente. Por favor, copie manualmente (Ctrl+C).');
            });
          });
        }
      })();
      // ##################################################################
      // ## FIM DA ADIÇÃO: Script do Modal de Validação
      // ##################################################################

    </script>
    ${idleLogoutScript}
    </body>
    </html>`;
};

// =====================
// Rotas Públicas
// =====================
app.get('/', (_req, res) => {
    res.type('html').send(page('Início', `
    <div class="grid md:grid-cols-2 gap-8 items-center">
      <div>
        <h1 class="text-3xl font-bold mb-4">Recadastramento Servo Atitude Kids</h1>
        <p class="mb-4">Para servir no ministério infantil, é necessário anexar a <strong>Certidão de Antecedentes Criminais (CAC)</strong>, aceitar o termo de privacidade (LGPD) e criar uma senha.</p>
        <div class="flex items-center gap-4">
            <a href="/cadastro" class="btn-brand px-5 py-3 rounded-lg">Começar cadastro</a>
            <a href="https://www.gov.br/pt-br/servicos/emitir-certidao-de-antecedentes-criminais" target="_blank" class="text-sm link-brand underline">Emitir CAC no Gov.br</a>
        </div>
      </div>
      <div class="bg-white border rounded-xl p-6">
        <h3 class="font-semibold mb-3">Funcionalidades do Sistema:</h3>
        <ul class="space-y-2 text-sm">
            <li>✔ Upload obrigatório da CAC (PDF)</li>
            <li>✔ Extração automática de dados do documento</li>
            <li>✔ Verificação automática de validade</li>
            <li>✔ Painel individual para atualização de dados</li>
            <li>✔ Painel de admin para acompanhamento geral</li>
        </ul>
      </div>
    </div>
  `));
});

app.get('/termo-lgpd', (_req, res) => {
    // Esta rota agora é menos necessária, mas pode ser mantida para acesso direto se desejado.
    // O conteúdo principal agora está no modal.
    res.type('html').send(page('Termo LGPD', `
    <div class="max-w-2xl mx-auto">
      <h2 class="text-2xl font-semibold mb-4">Termo de Consentimento e Privacidade</h2>
      <p>Autorizo a ${ORG} a utilizar minha CAC exclusivamente para avaliação de aptidão ao ministério infantil (Kids), conforme LGPD.</p>
      <ul class="list-disc ml-6 mt-3 space-y-1">
        <li>Acesso restrito e armazenamento seguro;</li>
        <li>Sem compartilhamento com terceiros;</li>
        <li>Guarda apenas durante a participação;</li>
        <li>Posso solicitar acesso/retificação/eliminação a qualquer momento.</li>
      </ul>
    </div>
  `));
});

// =====================
// Cadastro de voluntário
// =====================
app.get('/cadastro', (_req, res) => {
    // Corpo HTML da página de cadastro, incluindo o formulário e o modal oculto
    const bodyHtml = `
    <div class="max-w-xl mx-auto bg-white border rounded-xl p-6">
      <h2 class="text-2xl font-semibold mb-4">Crie sua conta</h2>
      <form method="post" action="/cadastro" enctype="multipart/form-data">
        <div class="space-y-4">
          <div><label class="block text-sm mb-1">Nome completo</label><input name="nome" required class="w-full border rounded px-3 py-2"/></div>
          <div><label class="block text-sm mb-1">CPF</label><input name="cpf" required placeholder="000.000.000-00" class="w-full border rounded px-3 py-2"/></div>
          
          <div>
            <label class="block text-sm mb-1">Rede</label>
            <select name="rede" required class="w-full border rounded px-3 py-2">
              <option value="">Selecione...</option>
              <option value="Amarela">Amarela</option>
              <option value="Vermelha">Vermelha</option>
              <option value="Verde">Verde</option>
              <option value="Branca">Branca</option>
              <option value="Laranja">Laranja</option>
              <option value="Azul">Azul</option>
            </select>
          </div>

          <div><label class="block text-sm mb-1">E-mail</label><input name="email" type="email" required class="w-full border rounded px-3 py-2"/></div>
          
          <div><label class="block text-sm mb-1">Telefone (WhatsApp)</label><input name="telefone" type="tel" placeholder="(21) 99999-9999" required class="w-full border rounded px-3 py-2"/></div>
          <div><label class="block text-sm mb-1">Nome do seu Coordenador</label><input name="nome_coordenador" required class="w-full border rounded px-3 py-2"/></div>

          <div>
            <label class="block text-sm mb-1">Senha</label>
            <div class="relative password-toggle-container">
              <input name="password" type="password" required class="w-full border rounded px-3 py-2 pr-10"/>
              <span class="password-toggle-icon absolute inset-y-0 right-0 pr-3 flex items-center cursor-pointer text-gray-500">
                <svg class="eye-icon h-5 w-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M2.036 12.322a1.012 1.012 0 010-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178z" /><path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /></svg>
                <svg class="eye-slash-icon hidden h-5 w-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M3.98 8.223A10.477 10.477 0 001.934 12C3.226 16.338 7.244 19.5 12 19.5c.993 0 1.953-.138 2.863-.395M6.228 6.228A10.45 10.45 0 0112 4.5c4.756 0 8.773 3.162 10.065 7.498a10.523 10.523 0 01-4.293 5.774M6.228 6.228L3 3m3.228 3.228l3.65 3.65m7.894 7.894L21 21m-3.228-3.228l-3.65-3.65m0 0a3 3 0 10-4.243-4.243m4.242 4.242L9.88 9.88" /></svg>
              </span>
            </div>
          </div>
          <div><label class="block text-sm mb-1">CAC (PDF até 2MB)</label><input type="file" name="cac_pdf" accept="application/pdf" required class="w-full"/></div>
          
          <div class="flex items-start gap-2">
            <input type="checkbox" name="consent" required class="mt-1" id="consent-checkbox">
            <label class="text-sm">Li e aceito o <button type="button" id="show-terms-btn" class="link-brand underline">termo de consentimento</button>.</label>
          </div>
          
          <button type="submit" class="btn-brand px-5 py-2.5 rounded w-full">Cadastrar</button>
        </div>
      </form>
    </div>

    <div id="terms-modal" class="fixed inset-0 bg-gray-800 bg-opacity-75 flex items-center justify-center p-4 hidden z-50">
      <div class="bg-white rounded-lg p-6 max-w-2xl w-full max-h-[80vh] overflow-y-auto">
        <h2 class="text-xl font-semibold mb-4">Termo de Consentimento e Privacidade</h2>
        <p>Autorizo a ${ORG} a utilizar minha CAC exclusivamente para avaliação de aptidão ao ministério infantil (Kids), conforme LGPD.</p>
        <ul class="list-disc ml-6 mt-3 space-y-1 text-sm">
          <li>Acesso restrito e armazenamento seguro;</li>
          <li>Sem compartilhamento com terceiros;</li>
          <li>Guarda apenas durante a participação;</li>
          <li>Posso solicitar acesso/retificação/eliminação a qualquer momento.</li>
        </ul>
        <div class="mt-6 flex justify-end gap-3">
           <button type="button" id="close-modal-btn" class="text-sm px-4 py-2 border rounded text-gray-600 hover:bg-gray-100">Fechar</button>
           <button type="button" id="accept-terms-btn" class="text-sm btn-brand px-4 py-2 rounded">Li e Aceito</button>
        </div>
      </div>
    </div>
    `;

    // JavaScript para controlar o modal
    const extraScripts = `
    <script>
      const showTermsBtn = document.getElementById('show-terms-btn');
      const termsModal = document.getElementById('terms-modal');
      const acceptTermsBtn = document.getElementById('accept-terms-btn');
      const closeModalBtn = document.getElementById('close-modal-btn');
      const consentCheckbox = document.getElementById('consent-checkbox');

      if (showTermsBtn && termsModal && acceptTermsBtn && closeModalBtn && consentCheckbox) {
        showTermsBtn.addEventListener('click', () => {
          termsModal.classList.remove('hidden');
        });

        acceptTermsBtn.addEventListener('click', () => {
          consentCheckbox.checked = true;
          termsModal.classList.add('hidden');
        });

        closeModalBtn.addEventListener('click', () => {
          termsModal.classList.add('hidden');
        });

        // Opcional: Fechar clicando fora do modal (na área escura)
        termsModal.addEventListener('click', (event) => {
          if (event.target === termsModal) {
            termsModal.classList.add('hidden');
          }
        });
      }
    </script>
    `;

    // Renderiza a página com o corpo HTML e o JavaScript extra
    res.type('html').send(page('Cadastro', bodyHtml, extraScripts));
});

app.post('/cadastro', upload.single('cac_pdf'), async (req, res, next) => {
    try {
        const { nome, cpf, email, password, consent, rede, telefone, nome_coordenador } = req.body;
        const cpfClean = (cpf || '').replace(/\D/g, '');
        const emailClean = (email || '').trim().toLowerCase();
        const telefoneClean = (telefone || '').replace(/\D/g, '');

        const { rows: existingUsers } = await pool.query(
            'SELECT id FROM cadastros WHERE cpf = $1 OR email = $2',
            [cpfClean, emailClean]
        );

        if (existingUsers.length > 0) {
            return res.status(409).send(page('Erro', '<p class="text-red-600 font-semibold">CPF ou E-mail já cadastrado. Se você já tem uma conta, por favor, <a href="/login" class="link-brand underline">faça o login</a>.</p>'));
        }

        if (!nome || !cpf || !email || !password || !rede || !telefone || !nome_coordenador || consent !== 'on' || !req.file)
            return res.status(400).send(page('Erro', '<p>Preencha todos os campos, aceite o termo e anexe o PDF.</p>'));

        if (!cpfValidator.isValid(cpfClean))
            return res.status(400).send(page('Erro', '<p>CPF inválido.</p>'));

        if (req.file.mimetype !== 'application/pdf')
            return res.status(400).send(page('Erro', '<p>Envie um PDF válido.</p>'));

        const password_hash = await bcrypt.hash(password, 10);
        const pdfBuffer = req.file.buffer;

        // ##################################################################
        // ## INÍCIO DA ATUALIZAÇÃO: Capturar data_nascimento
        // ##################################################################
        const { cert_number, issued_at, expires_at, cac_result, pdf_cpf, data_nascimento } = await extractFromPdf(pdfBuffer);
        // ##################################################################
        // ## FIM DA ATUALIZAÇÃO
        // ##################################################################

        if (!cert_number || !issued_at || !issued_at.isValid()) {
            return res.status(400).send(page('Erro', '<p class="text-red-600 font-semibold">O arquivo enviado não parece ser uma Certidão de Antecedentes Criminais válida. Por favor, emita o documento correto no site do Gov.br e tente novamente.</p>'));
        }

        // ##################################################################
        // ## INÍCIO DA NOVA TRAVA: CAC > 90 DIAS
        // ##################################################################
        const diasDesdeEmissao = dayjs().diff(issued_at, 'day');
        if (diasDesdeEmissao > 90) {
            return res.status(400).send(page('Documento Antigo', `
        <div class="bg-red-50 border-l-4 border-red-500 p-4">
            <p class="font-bold text-red-700">Atenção: Este CAC é muito antigo.</p>
            <p class="mt-2 text-sm text-red-800">Embora a validade interna seja de 6 meses, para realizarmos a <strong>validação de segurança na Polícia Federal</strong>, o documento precisa ter sido emitido há no máximo 90 dias.</p>
            <p class="mt-2 text-sm text-red-800">Seu documento foi emitido em <strong>${issued_at.format('DD/MM/YYYY')}</strong> (${diasDesdeEmissao} dias atrás).</p>
            <div class="mt-4">
                <a href="https://www.gov.br/pt-br/servicos/emitir-certidao-de-antecedentes-criminais" target="_blank" class="btn-brand px-4 py-2 rounded text-sm">Emitir CAC Novo no Gov.br</a>
            </div>
        </div>
    `));
        }
        // ##################################################################
        // ## FIM DA NOVA TRAVA
        // ##################################################################

        if (!pdf_cpf) {
            return res.status(400).send(page('Erro de Validação', '<p class="text-red-600 font-semibold">O documento enviado não contém um número de CPF. Por favor, emita uma nova Certidão no site do Gov.br, garantindo que o CPF seja incluído.</p>'));
        }
        if (pdf_cpf !== cpfClean) {
            return res.status(400).send(page('Erro de Validação', '<p class="text-red-600 font-semibold">O CPF informado no formulário não corresponde ao CPF encontrado no documento PDF. Por favor, envie o seu próprio documento.</p>'));
        }

        const pdf_sha256 = crypto.createHash('sha256').update(pdfBuffer).digest('hex');
        let status = 'em_revisao';
        if (issued_at && expires_at) {
            const now = dayjs();
            if (now.isAfter(expires_at)) {
                status = 'em_revisao'; // <-- MUDANÇA AQUI (era 'inapto', mas 'em_revisao' é melhor no cadastro)
            } else if (cac_result === 'nada_consta') {
                if (expires_at.diff(now, 'day') <= 15) {
                    status = 'atencao'; // <-- Mantido 'atencao' para "quase vencendo"
                } else {
                    status = 'apto';
                }
            }
        }
        const key = `cac/${Date.now()}_${cert_number}.pdf`;
        const { error: uploadError } = await supabase.storage
            .from(process.env.SUPABASE_BUCKET)
            .upload(key, pdfBuffer, { contentType: 'application/pdf', upsert: true });
        if (uploadError) throw uploadError;

        // ##################################################################
        // ## INÍCIO DA ATUALIZAÇÃO: Adicionar data_nascimento ao INSERT
        // ##################################################################
        const insert = `
      INSERT INTO cadastros
      (nome, cpf, email, password_hash, cert_number, issued_at, expires_at, status, pdf_path, pdf_sha256, cac_result, consent_signed_at, created_at, updated_at, rede, telefone, nome_coordenador, data_nascimento)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW(), NOW(), NOW(), $12, $13, $14, $15) RETURNING id
    `;
        const vals = [nome.trim(), cpfClean, emailClean, password_hash, cert_number, issued_at.toISOString(), expires_at.toISOString(), status, key, pdf_sha256, cac_result, rede, telefoneClean, nome_coordenador.trim(), (data_nascimento && data_nascimento.isValid()) ? data_nascimento.toISOString() : null];
        // ##################################################################
        // ## FIM DA ATUALIZAÇÃO
        // ##################################################################

        const { rows } = await pool.query(insert, vals);
        const token = signToken({ volunteer_id: rows[0].id, email: emailClean });
        res.cookie('vol_session', token, { httpOnly: true, sameSite: 'lax', secure: true });
        res.send(page('Conta criada', `<p>Cadastro concluído! Protocolo ${rows[0].id}. <a href="/meu/painel" class="link-brand underline">Ir para meu painel</a></p>`));
    } catch (e) {
        next(e);
    }
});

// =====================
// Login voluntário
// =====================
app.get('/login', setNoCacheHeaders, (_req, res) => {
    clearAllSessions(res);
    res.send(page('Login', `
    <div class="max-w-sm mx-auto bg-white border rounded-xl p-6">
      <h2 class="text-xl font-semibold mb-4">Login do Servo</h2>
      <form method="post" action="/login" class="space-y-3">
        <div><label class="block text-sm">E-mail</label><input name="email" type="email" class="w-full border rounded px-3 py-2" required/></div>
        <div>
          <label class="block text-sm">Senha</label>
          <div class="relative password-toggle-container">
            <input name="password" type="password" required class="w-full border rounded px-3 py-2 pr-10"/>
            <span class="password-toggle-icon absolute inset-y-0 right-0 pr-3 flex items-center cursor-pointer text-gray-500">
              <svg class="eye-icon h-5 w-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M2.036 12.322a1.012 1.012 0 010-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178z" /><path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /></svg>
              <svg class="eye-slash-icon hidden h-5 w-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M3.98 8.223A10.477 10.477 0 001.934 12C3.226 16.338 7.244 19.5 12 19.5c.993 0 1.953-.138 2.863-.395M6.228 6.228A10.45 10.45 0 0112 4.5c4.756 0 8.773 3.162 10.065 7.498a10.523 10.523 0 01-4.293 5.774M6.228 6.228L3 3m3.228 3.228l3.65 3.65m7.894 7.894L21 21m-3.228-3.228l-3.65-3.65m0 0a3 3 0 10-4.243-4.243m4.242 4.242L9.88 9.88" /></svg>
            </span>
          </div>
        </div>
        <button type="submit" class="btn-brand px-4 py-2 rounded w-full">Entrar</button>
      </form>
      <p class="text-sm mt-2"><a href="/forgot" class="link-brand underline">Esqueci minha senha</a></p>
    </div>
  `));
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body || {};
    const { rows } = await pool.query('SELECT id,password_hash FROM cadastros WHERE email=$1 LIMIT 1', [email?.trim().toLowerCase()]);
    if (!rows.length || !(await bcrypt.compare(password || '', rows[0].password_hash || '')))
        return res.send(page('Login', '<p>Credenciais inválidas.</p>'));

    const token = signToken({ volunteer_id: rows[0].id, email: (email || '').trim().toLowerCase() });
    res.cookie('vol_session', token, { httpOnly: true, sameSite: 'lax', secure: true });
    await pool.query('UPDATE cadastros SET last_login_at=NOW() WHERE id=$1', [rows[0].id]);
    res.redirect('/meu/painel');
});

// =====================
// Painel do voluntário
// =====================

app.post('/meu/check-subscription', requireVolunteer, async (req, res) => {
    try {
        const { endpoint } = req.body || {};
        const userId = req.vol.volunteer_id;

        if (!endpoint) {
            return res.json({ browserHasSubscription: false, userIsSubscribed: false });
        }

        const { rows } = await pool.query(
            'SELECT id FROM push_subscriptions WHERE endpoint = $1 AND user_id = $2',
            [endpoint, userId]
        );

        res.json({
            browserHasSubscription: true,
            userIsSubscribed: rows.length > 0,
        });
    } catch (e) {
        console.error("Erro ao checar inscrição:", e);
        res.status(500).json({ error: 'Erro ao checar inscrição.' });
    }
});

app.post('/meu/save-subscription', requireVolunteer, async (req, res) => {
    try {
        const subscription = req.body;
        const endpoint = subscription ? subscription.endpoint : null;
        const userId = req.vol.volunteer_id;
        
        if (!subscription || !endpoint) {
            return res.status(400).json({ error: 'Objeto de inscrição inválido.' });
        }

        const query = `
            INSERT INTO push_subscriptions (user_id, subscription, endpoint, created_at, updated_at)
            VALUES ($1, $2, $3, NOW(), NOW())
            ON CONFLICT (endpoint) 
            DO UPDATE SET 
                user_id = EXCLUDED.user_id,
                subscription = EXCLUDED.subscription,
                updated_at = NOW();
        `;
        
        await pool.query(query, [userId, subscription, endpoint]);

        const payload = JSON.stringify({
            title: 'Lembretes Ativados!',
            body: 'Tudo certo! Você será notificado quando for a hora de renovar seu CAC.'
        });
        await webpush.sendNotification(subscription, payload);

        res.status(201).json({ message: 'Inscrição salva com sucesso.' });
    } catch (error) {
        console.error("Erro ao salvar inscrição (upsert):", error);
        if (!res.headersSent) {
            res.status(500).json({ error: 'Erro ao processar a inscrição.' });
        }
    }
});

app.get('/meu/painel', requireVolunteer, setNoCacheHeaders, async (req, res) => {
    const { rows: userRows } = await pool.query('SELECT * FROM cadastros WHERE id=$1', [req.vol.volunteer_id]);
    if (userRows.length === 0) {
        return res.redirect('/login');
    }
    const r = userRows[0];

    const issued = r.issued_at ? dayjs(r.issued_at).format('DD/MM/YYYY') : '-';
    const exp = r.expires_at ? dayjs(r.expires_at).format('DD/MM/YYYY') : '-';
    
    const notificationSectionHtml = process.env.VAPID_PUBLIC_KEY ? `
        <div class="mt-6 p-4 bg-gray-100 rounded-lg border">
          <h3 class="font-semibold mb-2">Lembretes no Navegador</h3>
          <p class="text-sm mb-3">Ative as notificações para ser lembrado de renovar seu CAC diretamente no seu dispositivo.</p>
          <button id="subscribe-button" class="bg-green-600 text-white px-4 py-2 rounded-md text-sm hover:bg-green-700 disabled:bg-gray-400">Ativar Notificações</button>
          
          <div class="mt-2">
            <button id="btn-reinstalar-push" class="text-xs text-slate-600 underline hover:text-brand" type="button">
              Problemas com a notificação? Clique aqui para forçar a reinstalação.
            </button>
          </div>
          <p id="push-status" class="text-xs mt-2 text-slate-600"></p>
        </div>
    ` : '';

    // ##################################################################
    // ## INÍCIO DA ALTERAÇÃO: Lógica de Aviso Amarelo (Conforme Pedido)
    // ##################################################################
    
    let warningMessageHtml = ''; // Começa vazio
    
    // Checa se o status é 'em_revisao' E se o CAC está de fato expirado
    if (r.status === 'em_revisao' && r.expires_at && dayjs().isAfter(dayjs(r.expires_at))) {
        warningMessageHtml = `
        <div class="mb-4 p-4 bg-yellow-100 text-yellow-800 rounded-lg text-sm">
          <strong>Seu CAC precisa ser renovado.</strong>
          <p class="mt-1">Notamos que sua Certidão de Antecedentes Criminais expirou. Por favor, emita um novo documento no site do Gov.br e envie o PDF abaixo para reativar seu cadastro.</p>
        </div>
        `;
    }
    
    // O formulário de atualização (HTML puro)
    const updateFormContent = `
        <h3 class="font-semibold mb-2">Atualizar dados</h3>
        <form method="post" action="/meu/atualizar" enctype="multipart/form-data" class="space-y-3">
          <div><label class="block text-sm">Novo e-mail (opcional)</label><input name="email" type="email" class="w-full border rounded px-3 py-2" value="${r.email || ''}"/></div>
          <div><label class="block text-sm">Telefone (opcional)</label><input name="telefone" type="tel" class="w-full border rounded px-3 py-2" value="${r.telefone || ''}"/></div>
          <div><label class="block text-sm">Nome do Coordenador (opcional)</label><input name="nome_coordenador" type="text" class="w-full border rounded px-3 py-2" value="${r.nome_coordenador || ''}"/></div>
          <div>
            <label class="block text-sm">Sua Rede (opcional)</label>
            <select name="rede" class="w-full border rounded px-3 py-2">
              <option value="Amarela" ${r.rede === 'Amarela' ? 'selected' : ''}>Amarela</option>
              <option value="Vermelha" ${r.rede === 'Vermelha' ? 'selected' : ''}>Vermelha</option>
              <option value="Verde" ${r.rede === 'Verde' ? 'selected' : ''}>Verde</option>
              <option value="Branca" ${r.rede === 'Branca' ? 'selected' : ''}>Branca</option>
              <option value="Laranja" ${r.rede === 'Laranja' ? 'selected' : ''}>Laranja</option>
              <option value="Azul" ${r.rede === 'Azul' ? 'selected' : ''}>Azul</option>
            </select>
          </div>
          <div><label class="block text-sm">Nova CAC (PDF até 2MB, opcional)</label><input type="file" name="cac_pdf" accept="application/pdf" class="w-full"/></div>
          
          <div class="flex items-start gap-2">
            <input type="checkbox" name="consent" required class="mt-1" id="consent-checkbox-panel">
            <label class="text-sm">Confirmo novamente o <button type="button" id="show-terms-btn-panel" class="link-brand underline">termo de consentimento</button>.</label>
          </div>

          <button type="submit" class="btn-brand px-4 py-2 rounded">Salvar</button>
        </form>
    `;
    
    let updateFormHtml = '';
    
    // Define o que será mostrado
    if (r.status === 'inapto' || r.status === 'atencao') {
        // Se for 'inapto' ou 'atencao' (o antigo 'vencido'), bloqueia
        updateFormHtml = `
        <div class="mt-6 pt-6 border-t">
          <h3 class="font-semibold mb-2">Atualização Bloqueada</h3>
          <div class="text-sm text-amber-800 bg-amber-100 p-4 rounded-lg">
            <p>Seu cadastro foi marcado como <strong>${badge(r.status, r.cac_result)}</strong> pela administração.</p>
            <p class="mt-2">Para fazer alterações ou enviar um novo documento, por favor, entre em contato com a liderança do ministério.</p>
          </div>
        </div>`;
    } else {
        // Se for 'apto' OU 'em_revisao', mostra o formulário
        updateFormHtml = `
        <div class="mt-6 pt-6 border-t">
          ${updateFormContent}
        </div>`;
    }
    
    // ##################################################################
    // ## FIM DA ALTERAÇÃO
    // ##################################################################
    
    
    // HTML do modal para a página do painel
    const termsModalHtmlPanel = `
    <div id="terms-modal-panel" class="fixed inset-0 bg-gray-800 bg-opacity-75 flex items-center justify-center p-4 hidden z-50">
      <div class="bg-white rounded-lg p-6 max-w-2xl w-full max-h-[80vh] overflow-y-auto">
        <h2 class="text-xl font-semibold mb-4">Termo de Consentimento e Privacidade</h2>
        <p>Autorizo a ${ORG} a utilizar minha CAC exclusivamente para avaliação de aptidão ao ministério infantil (Kids), conforme LGPD.</p>
        <ul class="list-disc ml-6 mt-3 space-y-1 text-sm">
          <li>Acesso restrito e armazenamento seguro;</li>
          <li>Sem compartilhamento com terceiros;</li>
          <li>Guarda apenas durante a participação;</li>
          <li>Posso solicitar acesso/retificação/eliminação a qualquer momento.</li>
        </ul>
        <div class="mt-6 flex justify-end gap-3">
           <button type="button" id="close-modal-btn-panel" class="text-sm px-4 py-2 border rounded text-gray-600 hover:bg-gray-100">Fechar</button>
           <button type="button" id="accept-terms-btn-panel" class="text-sm btn-brand px-4 py-2 rounded">Li e Aceito</button>
        </div>
      </div>
    </div>
    `;

    // Combina o script de push com o script do modal do painel
    const combinedScripts = `
      <script>
      // Script original de Push Notifications (com checagem de usuário)
      (() => {
        const notificationContainer = document.getElementById('subscribe-button');
        if (!notificationContainer) return;

        const PUBLIC_VAPID = '${process.env.VAPID_PUBLIC_KEY}';
        const btnAtivar = document.getElementById('subscribe-button');
        const btnReinstalar = document.getElementById('btn-reinstalar-push');
        const statusEl = document.getElementById('push-status');

        const setStatus = (msg) => { if (statusEl) statusEl.textContent = msg; };
        const marcarAtivado = () => {
            if (btnAtivar) {
                btnAtivar.textContent = 'Notificações Ativadas';
                btnAtivar.disabled = true;
            }
        };
        const marcarDesativado = () => {
             if (btnAtivar) {
                btnAtivar.textContent = 'Ativar Notificações';
                btnAtivar.disabled = false;
            }
        }

        function urlBase64ToUint8Array(base64String) {
            const padding = '='.repeat((4 - base64String.length % 4) % 4);
            const base64 = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
            const raw = window.atob(base64);
            const output = new Uint8Array(raw.length);
            for (let i = 0; i < raw.length; ++i) output[i] = raw.charCodeAt(i);
            return output;
        }

        async function limparAntigos() {
            try {
                const regs = await navigator.serviceWorker.getRegistrations();
                await Promise.all(regs.map(r => r.unregister()));
                const keys = await caches.keys();
                await Promise.all(keys.map(k => caches.delete(k)));
            } catch (e) {
                console.warn('Falha ao limpar SW/cache:', e);
            }
        }

        async function registrarSW() {
            if (!('serviceWorker' in navigator)) throw new Error('Service Worker não é suportado');
            const reg = await navigator.serviceWorker.register('/service-worker.js');
            await navigator.serviceWorker.ready;
            return reg;
        }

        async function assinarPush(reg) {
            if (!('PushManager' in window)) throw new Error('Push não é suportado');
            if (Notification.permission === 'denied') throw new Error('Permissão de notificações está negada no navegador');

            let sub = await reg.pushManager.getSubscription();
            if (!sub) {
                if (Notification.permission === 'default') {
                    const perm = await Notification.requestPermission();
                    if (perm !== 'granted') throw new Error('Permissão não concedida');
                }
                sub = await reg.pushManager.subscribe({
                    userVisibleOnly: true,
                    applicationServerKey: urlBase64ToUint8Array(PUBLIC_VAPID)
                });
            }

            const resp = await fetch('/meu/save-subscription', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(sub)
            });
            if (!resp.ok) {
                await sub.unsubscribe().catch(e => console.error("Falha ao cancelar inscrição após erro do servidor", e));
                throw new Error('Falha ao salvar assinatura no servidor');
            }
            return sub;
        }
        
        async function reinstalar() {
            try {
                setStatus('Reinstalando, por favor aguarde…');
                if(btnAtivar) btnAtivar.disabled = true;
                if(btnReinstalar) btnReinstalar.disabled = true;

                await limparAntigos();
                const reg = await registrarSW();
                await assinarPush(reg);
                
                setStatus('Notificações ativadas com sucesso neste dispositivo!');
                marcarAtivado();
            } catch (e) {
                console.error('Erro na reinstalação:', e);
                setStatus('Erro: ' + (e?.message || e));
                marcarDesativado();
            } finally {
                if(btnReinstalar) btnReinstalar.disabled = false;
            }
        }
        
        async function ativar() {
             try {
                setStatus('Ativando...');
                if(btnAtivar) btnAtivar.disabled = true;
                const reg = await registrarSW();
                await assinarPush(reg);
                setStatus('Notificações ativadas com sucesso!');
                marcarAtivado();
            } catch (e) {
                console.warn('Ativação normal falhou:', e);
                setStatus('Erro ao ativar: ' + (e?.message || e) + '. Tentando reinstalar...');
                await reinstalar();
            }
        }

        async function initialize() {
            try {
                const reg = await navigator.serviceWorker.getRegistration();
                const sub = reg ? await reg.pushManager.getSubscription() : null;
                const endpoint = sub ? sub.endpoint : null;

                const checkResp = await fetch('/meu/check-subscription', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ endpoint })
                });
                
                if(!checkResp.ok) throw new Error('Falha na comunicação com o servidor');
                const status = await checkResp.json();

                if (status.browserHasSubscription && status.userIsSubscribed) {
                    setStatus('Lembretes já ativados para você neste dispositivo.');
                    marcarAtivado();
                } else {
                    setStatus('Lembretes não estão ativos para você neste navegador.');
                    marcarDesativado();
                }
            } catch(e) {
                console.error("Erro na inicialização da checagem:", e);
                setStatus('Não foi possível verificar o status das notificações.');
                if(btnAtivar) btnAtivar.disabled = true;
            }
        }

        if (!('serviceWorker' in navigator) || !('PushManager' in window)) {
            setStatus('Notificações Push não são suportadas neste navegador.');
            if(btnAtivar) btnAtivar.disabled = true;
            if(btnReinstalar) btnReinstalar.style.display = 'none';
        } else {
            if (btnAtivar) btnAtivar.addEventListener('click', ativar);
            if (btnReinstalar) btnReinstalar.addEventListener('click', reinstalar);
            
            window.addEventListener('load', initialize);
        }
      })();

      // Script para o Modal de Termos do Painel
      (() => {
        const showTermsBtnPanel = document.getElementById('show-terms-btn-panel');
        const termsModalPanel = document.getElementById('terms-modal-panel');
        const acceptTermsBtnPanel = document.getElementById('accept-terms-btn-panel');
        const closeModalBtnPanel = document.getElementById('close-modal-btn-panel');
        const consentCheckboxPanel = document.getElementById('consent-checkbox-panel');

        // Só executa se os elementos existirem (quando o formulário de update estiver visível)
        if (showTermsBtnPanel && termsModalPanel && acceptTermsBtnPanel && closeModalBtnPanel && consentCheckboxPanel) {
            showTermsBtnPanel.addEventListener('click', () => {
                termsModalPanel.classList.remove('hidden');
            });

            acceptTermsBtnPanel.addEventListener('click', () => {
                consentCheckboxPanel.checked = true;
                termsModalPanel.classList.add('hidden');
            });

            closeModalBtnPanel.addEventListener('click', () => {
                termsModalPanel.classList.add('hidden');
            });

            termsModalPanel.addEventListener('click', (event) => {
                if (event.target === termsModalPanel) {
                   termsModalPanel.classList.add('hidden');
                }
            });
        }
      })();
      </script>
    `;

    // Corpo HTML principal da página do painel
    const bodyHtmlPanel = `
    <div class="max-w-2xl mx-auto bg-white border rounded-xl p-6">
      <h2 class="text-2xl font-semibold mb-2">Olá, ${r.nome}</h2>
      <p class="text-sm mb-4">Status: ${badge(r.status, r.cac_result)}</p>
      
      ${warningMessageHtml} 
      
      <ul class="text-sm space-y-1 mb-4">
        <li><strong>E-mail:</strong> ${r.email}</li>
        <li><strong>Telefone:</strong> ${formatPhone(r.telefone)}</li>
        <li><strong>CPF:</strong> ${formatCPF(r.cpf)}</li>
        <li><strong>Rede:</strong> ${r.rede || '-'}</li>
        <li><strong>Coordenador:</strong> ${r.nome_coordenador || '-'}</li>
        <li><strong>Nº certidão:</strong> ${r.cert_number || '-'}</li>
        <li><strong>Emitida em:</strong> ${issued}</li>
        <li><strong>Válida até:</strong> ${exp}</li>
      </ul>
      
      ${r.pdf_path ? `<p><a href="/meu/ver-pdf" target="_blank" class="text-sm link-brand underline">Visualizar CAC enviado</a></p>` : ''}
      
      ${notificationSectionHtml}

      ${updateFormHtml}

      <p class="mt-6 text-sm"><a href="/logout" class="link-brand underline">Sair</a></p>
    </div>
    ${termsModalHtmlPanel} 
    `; // Adiciona o HTML do modal ao final do corpo

    res.send(page('Meu Painel', bodyHtmlPanel, combinedScripts)); // Passa os scripts combinados
});

app.get('/meu/ver-pdf', requireVolunteer, async (req, res) => {
    try {
        const id = req.vol.volunteer_id;
        const { rows } = await pool.query('SELECT pdf_path FROM cadastros WHERE id=$1', [id]);
        if (!rows.length || !rows[0].pdf_path) {
            return res.status(404).send('PDF não encontrado.');
        }
        const key = rows[0].pdf_path;
        const { data, error } = await supabase.storage.from(process.env.SUPABASE_BUCKET).download(key);
        if (error) throw error;
        const buffer = Buffer.from(await data.arrayBuffer());
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Length', buffer.length);
        res.send(buffer);
    } catch (e) {
        console.error('Erro ao buscar PDF do usuário no Supabase:', e);
        res.status(500).send('Erro ao carregar o arquivo.');
    }
});

app.get('/logout', (req, res) => {
    clearAllSessions(res);
    res.redirect('/login');
});

app.post('/meu/atualizar', requireVolunteer, upload.single('cac_pdf'), async (req, res, next) => {
    try {
        const id = req.vol.volunteer_id;
        const { rows: currentUserRows } = await pool.query('SELECT cpf, pdf_path, status FROM cadastros WHERE id = $1', [id]);
        if (currentUserRows.length === 0) {
            return res.status(404).send(page('Erro', '<p>Usuário não encontrado.</p>'));
        }
        const currentUser = currentUserRows[0];
        const currentStatus = currentUser.status;
        const oldPdfPath = currentUser.pdf_path;
        const cpfClean = currentUser.cpf;

        // ##################################################################
        // ## INÍCIO DA ALTERAÇÃO: Lógica de Bloqueio
        // ##################################################################
        
        // Agora, 'em_revisao' é permitido, 'atencao' continua bloqueado
        if (currentStatus === 'inapto' || currentStatus === 'atencao') {
            return res.status(403).send(page('Atualização Bloqueada', '<p class="text-red-600 font-semibold">Sua conta está com um status que não permite atualizações automáticas. Por favor, entre em contato com a administração.</p>'));
        }
        
        // ##################################################################
        // ## FIM DA ALTERAÇÃO
        // ##################################################################


        if (req.body.consent !== 'on') return res.status(400).send(page('Erro', '<p>Você precisa confirmar o termo de consentimento.</p>'));

        const updates = [];
        const params = [];
        let idx = 1;

        if (req.body.email) {
            updates.push(`email=$${idx++}`);
            params.push(req.body.email.trim().toLowerCase());
        }

        if (req.body.rede) {
            updates.push(`rede = $${idx++}`);
            params.push(req.body.rede);
        }

        if (req.body.telefone) {
            const telefoneClean = (req.body.telefone || '').replace(/\D/g, '');
            updates.push(`telefone = $${idx++}`);
            params.push(telefoneClean);
        }

        if (req.body.nome_coordenador) {
            updates.push(`nome_coordenador = $${idx++}`);
            params.push(req.body.nome_coordenador.trim());
        }

        if (req.file) {
            if (req.file.mimetype !== 'application/pdf') return res.status(400).send(page('Erro', '<p>Envie um PDF válido.</p>'));

            const pdfBuffer = req.file.buffer;
            
            // ##################################################################
            // ## INÍCIO DA ATUALIZAÇÃO: Capturar data_nascimento (no update)
            // ##################################################################
            const { cert_number, issued_at, expires_at, cac_result, pdf_cpf, data_nascimento } = await extractFromPdf(pdfBuffer);
            // ##################################################################
            // ## FIM DA ATUALIZAÇÃO
            // ##################################################################

            // ##################################################################
            // ## INÍCIO DA NOVA TRAVA: CAC > 90 DIAS (UPDATE)
            // ##################################################################
            if (issued_at && issued_at.isValid()) {
                const diasDesdeEmissao = dayjs().diff(issued_at, 'day');
                if (diasDesdeEmissao > 90) {
                    return res.status(400).send(page('Documento Antigo', `
                <div class="bg-red-50 border-l-4 border-red-500 p-4">
                    <p class="font-bold text-red-700">Não foi possível atualizar.</p>
                    <p class="mt-2 text-sm text-red-800">Este CAC foi emitido há mais de 90 dias (em ${issued_at.format('DD/MM/YYYY')}).</p>
                    <p class="mt-1 text-sm text-red-800">Para validar sua renovação, precisamos de um documento recente.</p>
                    <div class="mt-4">
                        <a href="https://www.gov.br/pt-br/servicos/emitir-certidao-de-antecedentes-criminais" target="_blank" class="btn-brand px-4 py-2 rounded text-sm">Emitir CAC Novo no Gov.br</a>
                        <a href="/meu/painel" class="ml-3 text-sm underline text-slate-600">Voltar</a>
                    </div>
                </div>
            `));
                }
            }
            // ##################################################################
            // ## FIM DA NOVA TRAVA
            // ##################################################################

            if (!pdf_cpf) {
                return res.status(400).send(page('Erro de Validação', '<p class="text-red-600 font-semibold">O novo documento enviado não contém um CPF. Por favor, emita e envie uma Certidão que inclua seu CPF.</p>'));
            }
            if (pdf_cpf !== cpfClean) {
                return res.status(400).send(page('Erro de Validação', '<p class="text-red-600 font-semibold">O CPF no novo documento não corresponde ao seu CPF cadastrado. Por favor, envie o seu próprio documento.</p>'));
            }

            const key = `cac/${Date.now()}_${cert_number || 'sem-numero'}.pdf`;
            const { error: uploadError } = await supabase.storage.from(process.env.SUPABASE_BUCKET).upload(key, pdfBuffer, { contentType: 'application/pdf', upsert: true });
            if (uploadError) throw uploadError;

            const pdf_sha256 = crypto.createHash('sha256').update(pdfBuffer).digest('hex');
            updates.push(`cert_number=$${idx++}`); params.push(cert_number);
            updates.push(`issued_at=$${idx++}`); params.push((issued_at && issued_at.isValid()) ? issued_at.toISOString() : null);
            updates.push(`expires_at=$${idx++}`); params.push((expires_at && expires_at.isValid()) ? expires_at.toISOString() : null);
            updates.push(`pdf_path=$${idx++}`); params.push(key);
            updates.push(`pdf_sha256=$${idx++}`); params.push(pdf_sha256);
            updates.push(`cac_result=$${idx++}`); params.push(cac_result);

            // ##################################################################
            // ## INÍCIO DA ATUALIZAÇÃO: Adicionar data_nascimento (no update)
            // ##################################################################
            updates.push(`data_nascimento=$${idx++}`); params.push((data_nascimento && data_nascimento.isValid()) ? data_nascimento.toISOString() : null);
            // ##################################################################
            // ## FIM DA ATUALIZAÇÃO
            // ##################################################################

            let newStatus = 'em_revisao';
            if (issued_at && expires_at && issued_at.isValid()) {
                const now = dayjs();
                if (now.isAfter(expires_at)) {
                    newStatus = 'em_revisao'; // <-- MUDANÇA AQUI (era 'inapto')
                } else if (cac_result === 'nada_consta') {
                    if (expires_at.diff(now, 'day') <= 15) {
                        newStatus = 'atencao';
                    } else {
                        newStatus = 'apto';
                    }
                }
            }
            updates.push(`status=$${idx++}`); params.push(newStatus);
        }

        updates.push(`consent_signed_at=NOW()`);
        updates.push(`updated_at=NOW()`);

        params.push(id);
        const q = `UPDATE cadastros SET ${updates.join(', ')} WHERE id=$${idx} RETURNING id`;
        await pool.query(q, params);

        if (req.file && oldPdfPath) {
            try {
                await supabase.storage.from(process.env.SUPABASE_BUCKET).remove([oldPdfPath]);
            } catch (removeError) {
                console.error("Erro ao deletar PDF antigo, mas o cadastro foi atualizado:", removeError);
            }
        }

        res.redirect('/meu/painel');
    } catch (e) {
        next(e);
    }
});

app.get('/forgot', setNoCacheHeaders, (_req, res) => {
    res.send(page('Esqueci minha senha', `
    <div class="max-w-sm mx-auto bg-white border rounded-xl p-6">
      <h2 class="text-xl font-semibold mb-3">Recuperar senha</h2>
      <p class="text-sm mb-4">Digite o e-mail associado à sua conta e enviaremos um link para redefinir sua senha.</p>
      <form method="post" action="/forgot" class="space-y-3">
        <div><label class="block text-sm">E-mail</label><input name="email" type="email" class="w-full border rounded px-3 py-2" required/></div>
        <button type="submit" class="btn-brand px-4 py-2 rounded w-full">Enviar link de recuperação</button>
      </form>
    </div>
  `));
});

app.post('/forgot', async (req, res) => {
    const email = (req.body.email || '').trim().toLowerCase();
    const { rows } = await pool.query('SELECT id FROM cadastros WHERE email=$1 LIMIT 1', [email]);
    if (!rows.length) return res.send(page('OK', '<p>Se existir conta com este e-mail, enviaremos um link para recuperação de senha.</p>'));

    const token = crypto.randomBytes(24).toString('hex');
    await pool.query('UPDATE cadastros SET reset_token=$1, reset_expires=NOW()+INTERVAL \'1 day\' WHERE id=$2', [token, rows[0].id]);

    const baseUrl = (process.env.APP_BASE_URL || '').replace(/\/$/, '');
    const link = `${baseUrl}/reset?token=${token}`;

    if (transporter) {
        try {
            await transporter.sendMail({
                from: process.env.MAIL_FROM || 'no-reply@example.com', to: email,
                subject: 'Redefinição de senha', html: `Clique aqui para redefinir sua senha: <a href="${link}">${link}</a>`
            });
        } catch (mailError) {
            console.error("Erro ao enviar e-mail de recuperação:", mailError);
        }
    }

    res.send(page('OK', `<p>Se existir uma conta com o e-mail informado, um link para recuperação de senha foi enviado. Por favor, verifique sua caixa de entrada e spam.</p>`));
});

app.get('/reset', async (req, res) => {
    const { rows } = await pool.query('SELECT id FROM cadastros WHERE reset_token=$1 AND reset_expires>NOW() LIMIT 1', [req.query.token]);
    if (!rows.length) return res.send(page('Reset', '<p>Link inválido ou expirado.</p>'));
    res.send(page('Definir nova senha', `
    <div class="max-w-sm mx-auto bg-white border rounded-xl p-6">
      <h2 class="text-xl font-semibold mb-3">Definir Nova Senha</h2>
      <form method="post" action="/reset?token=${req.query.token}" class="space-y-3">
        <div>
          <label class="block text-sm">Nova senha</label>
          <div class="relative password-toggle-container">
            <input name="password" type="password" required class="w-full border rounded px-3 py-2 pr-10"/>
            <span class="password-toggle-icon absolute inset-y-0 right-0 pr-3 flex items-center cursor-pointer text-gray-500">
              <svg class="eye-icon h-5 w-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M2.036 12.322a1.012 1.012 0 010-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178z" /><path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /></svg>
              <svg class="eye-slash-icon hidden h-5 w-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M3.98 8.223A10.477 10.477 0 001.934 12C3.226 16.338 7.244 19.5 12 19.5c.993 0 1.953-.138 2.863-.395M6.228 6.228A10.45 10.45 0 0112 4.5c4.756 0 8.773 3.162 10.065 7.498a10.523 10.523 0 01-4.293 5.774M6.228 6.228L3 3m3.228 3.228l3.65 3.65m7.894 7.894L21 21m-3.228-3.228l-3.65-3.65m0 0a3 3 0 10-4.243-4.243m4.242 4.242L9.88 9.88" /></svg>
            </span>
          </div>
        </div>
        <button type="submit" class="btn-brand px-4 py-2 rounded">Salvar</button>
      </form>
    </div>
  `));
});

app.post('/reset', async (req, res) => {
    const token = req.query.token;
    const { rows } = await pool.query('SELECT id FROM cadastros WHERE reset_token=$1 AND reset_expires>NOW() LIMIT 1', [token]);
    if (!rows.length) return res.send(page('Reset', '<p>Link inválido ou expirado.</p>'));
    const hash = await bcrypt.hash(req.body.password || '', 10);
    await pool.query('UPDATE cadastros SET password_hash=$1, reset_token=NULL, reset_expires=NULL WHERE id=$2', [hash, rows[0].id]);
    res.send(page('OK', '<p>Senha atualizada com sucesso. <a href="/login" class="link-brand underline">Clique aqui para entrar</a>.</p>'));
});

// =====================
// Admin
// =====================
app.get('/admin/login', setNoCacheHeaders, (req, res) => {
    clearAllSessions(res);
    const timeoutMessage = req.query.timeout === '1'
      ? '<div class="mb-4 p-3 bg-yellow-100 text-yellow-800 text-sm rounded-lg">Sua sessão expirou por inatividade. Por favor, faça o login novamente.</div>'
      : '';
      
    res.send(adminPage('Login Admin', `
    <div class="max-w-sm mx-auto bg-white border rounded-xl p-6">
      <h2 class="text-xl font-semibold mb-4">Acesso do administrador</h2>
      ${timeoutMessage}
      <form method="post" action="/admin/login" class="space-y-3">
        <div><label class="block text-sm">E-mail</label><input name="email" class="w-full border rounded px-3 py-2" required/></div>
        <div>
          <label class="block text-sm">Senha</label>
          <div class="relative password-toggle-container">
            <input name="password" type="password" required class="w-full border rounded px-3 py-2 pr-10"/>
            <span class="password-toggle-icon absolute inset-y-0 right-0 pr-3 flex items-center cursor-pointer text-gray-500">
              <svg class="eye-icon h-5 w-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M2.036 12.322a1.012 1.012 0 010-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178z" /><path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /></svg>
              <svg class="eye-slash-icon hidden h-5 w-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M3.98 8.223A10.477 10.477 0 001.934 12C3.226 16.338 7.244 19.5 12 19.5c.993 0 1.953-.138 2.863-.395M6.228 6.228A10.45 10.45 0 0112 4.5c4.756 0 8.773 3.162 10.065 7.498a10.523 10.523 0 01-4.293 5.774M6.228 6.228L3 3m3.228 3.228l3.65 3.65m7.894 7.894L21 21m-3.228-3.228l-3.65-3.65m0 0a3 3 0 10-4.243-4.243m4.242 4.242L9.88 9.88" /></svg>
            </span>
          </div>
        </div>
        <button type="submit" class="btn-brand px-4 py-2 rounded w-full">Entrar</button>
      </form>
      <p class="text-sm mt-2"><a href="/admin/forgot" class="link-brand underline">Esqueci minha senha</a></p>
    </div>
  `));
});

app.post('/admin/login', async (req,res)=>{
  const { email, password } = req.body || {};
  if (email === process.env.SUPER_ADMIN_EMAIL && password === process.env.SUPER_ADMIN_PASS) {
    const t = signToken({ role: 'admin:super', email, admin_id: 0 }, 'SESSION_SECRET');
    res.cookie('admin_session', t, { httpOnly: true, sameSite:'lax', secure:true });
    return res.redirect('/admin/painel');
  }
  const { rows } = await pool.query('SELECT id,password_hash,role FROM admins WHERE email=$1 LIMIT 1', [email?.trim()]);
  if (!rows.length || !(await bcrypt.compare(password || '', rows[0].password_hash || '')))
    return res.send(adminPage('Login', '<p>Credenciais inválidas.</p>'));
  const token = signToken({ role: `admin:${rows[0].role}`, email: email.trim(), admin_id: rows[0].id });
  res.cookie('admin_session', token, { httpOnly: true, sameSite:'lax', secure:true });
  res.redirect('/admin/painel');
});

app.get('/admin/forgot', setNoCacheHeaders, (_req, res) => {
  res.send(adminPage('Esqueci minha senha', `
    <div class="max-w-sm mx-auto bg-white border rounded-xl p-6">
      <h2 class="text-xl font-semibold mb-3">Recuperar senha de Administrador</h2>
      <p class="text-sm mb-4">Digite o e-mail associado à sua conta de admin e enviaremos um link para redefinir sua senha.</p>
      <form method="post" action="/admin/forgot" class="space-y-3">
        <div><label class="block text-sm">E-mail</label><input name="email" type="email" class="w-full border rounded px-3 py-2" required/></div>
        <button type="submit" class="btn-brand px-4 py-2 rounded w-full">Enviar link de recuperação</button>
      </form>
    </div>
  `));
});

app.post('/admin/forgot', async (req, res, next) => {
  try {
    const email = (req.body.email || '').trim().toLowerCase();
    const { rows } = await pool.query('SELECT id FROM admins WHERE email=$1 LIMIT 1', [email]);
    
    if (!rows.length) {
      return res.send(adminPage('OK', '<p>Se existir uma conta de administrador com este e-mail, enviaremos um link para recuperação de senha.</p>'));
    }

    const token = crypto.randomBytes(24).toString('hex');
    await pool.query('UPDATE admins SET reset_token=$1, reset_expires=NOW()+INTERVAL \'1 day\' WHERE id=$2', [token, rows[0].id]);
    
    const baseUrl = (process.env.APP_BASE_URL || '').replace(/\/$/, '');
    const link = `${baseUrl}/admin/reset?token=${token}`;

    if (transporter) {
      await transporter.sendMail({
        from: process.env.MAIL_FROM || 'no-reply@example.com',
        to: email,
        subject: `Redefinição de senha Admin - ${ORG}`,
        html: `Clique aqui para redefinir sua senha de administrador: <a href="${link}">${link}</a>`
      });
    }

    res.send(adminPage('OK', `<p>Se existir uma conta de administrador com o e-mail informado, um link para recuperação de senha foi enviado. Por favor, verifique sua caixa de entrada e spam.</p>`));
  } catch (e) {
    next(e);
  }
});

app.get('/admin/reset', setNoCacheHeaders, async (req, res, next) => {
  try {
    const { rows } = await pool.query('SELECT id FROM admins WHERE reset_token=$1 AND reset_expires>NOW() LIMIT 1', [req.query.token]);
    if (!rows.length) return res.send(adminPage('Reset', '<p>Link inválido ou expirado.</p>'));
    
    res.send(adminPage('Definir nova senha de Admin', `
      <div class="max-w-sm mx-auto bg-white border rounded-xl p-6">
        <h2 class="text-xl font-semibold mb-3">Definir Nova Senha de Admin</h2>
        <form method="post" action="/admin/reset?token=${req.query.token}" class="space-y-3">
          <div>
            <label class="block text-sm">Nova senha</label>
            <div class="relative password-toggle-container">
              <input name="password" type="password" required class="w-full border rounded px-3 py-2 pr-10"/>
              <span class="password-toggle-icon absolute inset-y-0 right-0 pr-3 flex items-center cursor-pointer text-gray-500">
                <svg class="eye-icon h-5 w-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M2.036 12.322a1.012 1.012 0 010-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178z" /><path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /></svg>
              <svg class="eye-slash-icon hidden h-5 w-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M3.98 8.223A10.477 10.477 0 001.934 12C3.226 16.338 7.244 19.5 12 19.5c.993 0 1.953-.138 2.863-.395M6.228 6.228A10.45 10.45 0 0112 4.5c4.756 0 8.773 3.162 10.065 7.498a10.523 10.523 0 01-4.293 5.774M6.228 6.228L3 3m3.228 3.228l3.65 3.65m7.894 7.894L21 21m-3.228-3.228l-3.65-3.65m0 0a3 3 0 10-4.243-4.243m4.242 4.242L9.88 9.88" /></svg>
              </span>
            </div>
          </div>
          <button type="submit" class="btn-brand px-4 py-2 rounded">Salvar</button>
        </form>
      </div>
    `));
  } catch (e) {
    next(e);
  }
});

app.post('/admin/reset', async (req, res, next) => {
  try {
    const token = req.query.token;
    const { rows } = await pool.query('SELECT id FROM admins WHERE reset_token=$1 AND reset_expires>NOW() LIMIT 1', [token]);
    if (!rows.length) return res.send(adminPage('Reset', '<p>Link inválido ou expirado.</p>'));
    
    const hash = await bcrypt.hash(req.body.password || '', 10);
    await pool.query('UPDATE admins SET password_hash=$1, reset_token=NULL, reset_expires=NULL WHERE id=$2', [hash, rows[0].id]);
    
    res.send(adminPage('OK', '<p>Senha de administrador atualizada com sucesso. <a href="/admin/login" class="link-brand underline">Clique aqui para entrar</a>.</p>'));
  } catch (e) {
    next(e);
  }
});

app.get('/admin/logout', (req, res) => {
  clearAllSessions(res);
  // Redireciona para login, o parâmetro timeout=1 é opcional se não for usado no front-end
  res.redirect('/admin/login?timeout=1'); 
});


app.get('/admin/painel', requireAdmin, setNoCacheHeaders, async (req,res)=>{
  const adminData = verifyToken(req.cookies['admin_session']);
  
  const { nome, email, status, rede } = req.query;
  let query = 'SELECT id,nome,cpf,email,cert_number,issued_at,expires_at,status,cac_result,pdf_path,rede,telefone,nome_coordenador,data_nascimento FROM cadastros WHERE 1=1'; // <-- ADICIONADO data_nascimento
  const params = [];

  if (nome) {
    params.push(`%${nome}%`);
    query += ` AND nome ILIKE $${params.length}`;
  }
  if (email) {
    params.push(`%${email}%`);
    query += ` AND email ILIKE $${params.length}`;
  }
  if (status) {
    params.push(status);
    query += ` AND status = $${params.length}`;
  }
  if (rede) {
    params.push(rede);
    query += ` AND rede = $${params.length}`;
  }

  query += ' ORDER BY created_at DESC LIMIT 500';
  const { rows } = await pool.query(query, params);
  
  const tr = rows.map(r=>{
    const issued = r.issued_at ? dayjs(r.issued_at).format('DD/MM/YYYY') : '-';
    const exp = r.expires_at ? dayjs(r.expires_at).format('DD/MM/YYYY') : '-';
    
    // ##################################################################
    // ## INÍCIO DA ATUALIZAÇÃO: Link de validação (agora é um botão modal)
    // ##################################################################
    const dataNascFormatada = r.data_nascimento ? dayjs(r.data_nascimento).format('DD/MM/YYYY') : '';
    const acaoValidar = r.cert_number
      ? `<button type="button" 
                 class="btn-validar-pf link-brand underline" 
                 data-nome="${r.nome.replace(/"/g, '&quot;')}" 
                 data-cert="${r.cert_number}" 
                 data-nasc="${dataNascFormatada}">
           Validar na PF
         </button>`
      : '-';
    // ##################################################################
    // ## FIM DA ATUALIZAÇÃO
    // ##################################################################
      
    const acaoVerPdf = r.pdf_path ? `<a target="_blank" href="/admin/ver-pdf/${r.id}" class="link-brand underline">Ver PDF</a>` : '-';

    const statusForm = `
      <form action="/admin/update-status" method="post" class="flex items-center gap-2">
        <input type="hidden" name="id" value="${r.id}" />
        <select name="status" class="border rounded text-xs p-1">
          <option value="em_revisao" ${r.status === 'em_revisao' ? 'selected' : ''}>Em revisão</option>
          <option value="apto" ${r.status === 'apto' ? 'selected' : ''}>Apto</option>
          <option value="atencao" ${r.status === 'atencao' ? 'selected' : ''}>Atenção</option>
          <option value="inapto" ${r.status === 'inapto' ? 'selected' : ''}>Inapto</option>
        </select>
        <button class="bg-blue-500 text-white px-2 py-1 rounded text-xs hover:bg-blue-600">Salvar</button>
      </form>
    `;

    const deleteForm = `
      <form action="/admin/delete-servo" method="post" onsubmit="return confirm('Tem certeza que deseja excluir este servo? Esta ação não pode ser desfeita.');">
        <input type="hidden" name="id" value="${r.id}" />
        <button type="submit" class="text-red-500 hover:text-red-700 text-xl">🗑️</button>
      </form>
    `;

    return `<tr class="border-b">
      <td class="py-2 px-3">${deleteForm}</td>
      <td class="py-2 px-3">${r.id}</td>
      <td class="py-2 px-3">${r.nome}</td>
      <td class="py-2 px-3">${formatCPF(r.cpf)}</td>
      <td class="py-2 px-3">${formatPhone(r.telefone)}</td>
      <td class="py-2 px-3">${r.rede || '-'}</td>
      <td class="py-2 px-3">${r.nome_coordenador || '-'}</td>
      <td class="py-2 px-3">${r.email}</td>
      <td class="py-2 px-3">${r.cert_number||'-'}</td>
      <td class="py-2 px-3">${issued}</td>
      <td class="py-2 px-3">${exp}</td>
      <td class="py-2 px-3">${badge(r.status,r.cac_result)}</td>
      <td class="py-2 px-3">${statusForm}</td>
      <td class="py-2 px-3">${acaoValidar}</td>
      <td class="py-2 px-3">${acaoVerPdf}</td>
    </tr>`;
  }).join('');

  const filtersHtml = `
    <form method="get" class="mb-6 grid grid-cols-2 md:grid-cols-5 gap-3 bg-white p-4 rounded-lg border items-end">
      <div class="col-span-2 md:col-span-1"><label class="text-xs font-semibold text-slate-600">Nome</label><input type="text" name="nome" value="${nome || ''}" class="border rounded px-3 py-2 w-full mt-1"></div>
      <div class="col-span-2 md:col-span-1"><label class="text-xs font-semibold text-slate-600">E-mail</label><input type="text" name="email" value="${email || ''}" class="border rounded px-3 py-2 w-full mt-1"></div>
      <div class="col-span-1"><label class="text-xs font-semibold text-slate-600">Status</label><select name="status" class="border rounded px-3 py-2 w-full mt-1">
        <option value="">Todos</option>
        <option value="apto" ${status === 'apto' ? 'selected' : ''}>Apto</option>
        <option value="inapto" ${status === 'inapto' ? 'selected' : ''}>Inapto</option>
        <option value="atencao" ${status === 'atencao' ? 'selected' : ''}>Atenção</option>
        <option value="em_revisao" ${status === 'em_revisao' ? 'selected' : ''}>Em revisão</option>
      </select></div>
      <div class="col-span-1"><label class="text-xs font-semibold text-slate-600">Rede</label><select name="rede" class="border rounded px-3 py-2 w-full mt-1">
        <option value="">Todas</option>
        <option value="Amarela" ${rede === 'Amarela' ? 'selected' : ''}>Amarela</option>
        <option value="Vermelha" ${rede === 'Vermelha' ? 'selected' : ''}>Vermelha</option>
        <option value="Verde" ${rede === 'Verde' ? 'selected' : ''}>Verde</option>
        <option value="Branca" ${rede === 'Branca' ? 'selected' : ''}>Branca</option>
        <option value="Laranja" ${rede === 'Laranja' ? 'selected' : ''}>Laranja</option>
        <option value="Azul" ${rede === 'Azul' ? 'selected' : ''}>Azul</option>
      </select></div>
      <div class="col-span-2 md:col-span-1 flex justify-start gap-2">
        <button type="submit" class="btn-brand px-4 py-2 rounded">Filtrar</button>
        <a href="/admin/painel" class="px-4 py-2 border rounded text-slate-600 hover:bg-slate-100">Limpar</a>
      </div>
    </form>
  `;
  
  // Alteração: Mover o botão "Gerenciar Admins" para o topo
  res.send(adminPage('Painel Admin', `
    <div class="flex justify-between items-center mb-4">
      <h2 class="text-2xl font-semibold">Cadastros</h2>
      <a href="/admin/admins" class="btn-brand px-4 py-2 rounded text-sm">Gerenciar Admins</a>
    </div>
    
    ${filtersHtml}
    <div class="overflow-x-auto bg-white border rounded-xl mb-6">
      <table class="min-w-full text-sm">
        <thead class="bg-slate-100"><tr>
            <th class="px-3 py-2 text-left">Ação</th>
            <th class="px-3 py-2 text-left">ID</th>
            <th class="px-3 py-2 text-left">Nome Completo</th>
            <th class="px-3 py-2 text-left">CPF</th>
            <th class="px-3 py-2 text-left">Telefone</th>
            <th class="px-3 py-2 text-left">Rede</th>
            <th class="px-3 py-2 text-left">Coordenador</th>
            <th class="px-3 py-2 text-left">E-mail</th>
            <th class="px-3 py-2 text-left">Certidão</th>
            <th class="px-3 py-2 text-left">Emissão</th>
            <th class="px-3 py-2 text-left">Validade</th>
            <th class="px-3 py-2 text-left">Status Badge</th>
            <th class="px-3 py-2 text-left">Mudar Status</th>
            <th class="px-3 py-2 text-left">Validar</th>
            <th class="px-3 py-2 text-left">PDF</th>
        </tr></thead>
        <tbody>${tr || `<tr><td colspan="15" class="py-6 text-center text-slate-500">Sem registros</td></tr>`}</tbody>
      </table>
    </div>
  `, adminData)); // Botão removido do final
});

app.post('/admin/update-status', requireAdmin, async (req, res) => {
  try {
    const { id, status } = req.body;
    const allowedStatus = ['em_revisao', 'apto', 'atencao', 'inapto'];
    if (!id || !allowedStatus.includes(status)) {
      return res.status(400).send('Dados inválidos.');
    }
    
    await pool.query('UPDATE cadastros SET status = $1, updated_at = NOW() WHERE id = $2', [status, id]);
    res.redirect('/admin/painel');
  } catch(e) {
    console.error(e);
    res.status(500).send('Erro ao atualizar status.');
  }
});

app.post('/admin/delete-servo', requireAdmin, async (req, res) => {
    try {
        const { id } = req.body;
        if (!id) {
            return res.status(400).send('ID do servo não fornecido.');
        }

        const { rows } = await pool.query('SELECT pdf_path FROM cadastros WHERE id = $1', [id]);
        
        if (rows.length === 0) {
            return res.status(404).send('Servo não encontrado.');
        }
        const pdfPath = rows[0].pdf_path;

        await pool.query('DELETE FROM cadastros WHERE id = $1', [id]);

        if (pdfPath) {
            try {
                await supabase.storage.from(process.env.SUPABASE_BUCKET).remove([pdfPath]);
            } catch (storageError) {
                console.error(`Falha ao apagar o arquivo ${pdfPath} do storage, mas o registro do servo foi removido do banco.`, storageError);
            }
        }

        res.redirect('/admin/painel');
    } catch (e) {
        console.error(e);
        res.status(500).send('Erro ao deletar o servo.');
    }
});

app.get('/admin/admins', requireSuper, setNoCacheHeaders, async (req,res)=>{
    const adminData = verifyToken(req.cookies['admin_session']);
    const { rows } = await pool.query('SELECT id,email,role,created_at FROM admins ORDER BY created_at DESC');
    const tr = rows.map(a=>{
      let deleteForm = '';
      let roleEditor = `<td class="py-2 px-3">${a.role}</td>`;
  
      if (adminData.role === 'admin:super' && a.email.toLowerCase() !== adminData.email.toLowerCase() && a.email !== process.env.SUPER_ADMIN_EMAIL) {
          deleteForm = `
                <form action="/admin/delete-admin" method="post" onsubmit="return confirm('Tem certeza que deseja excluir este administrador?');">
                    <input type="hidden" name="id" value="${a.id}" />
                    <button type="submit" class="text-red-500 hover:text-red-700 text-xl">🗑️</button>
                </form>
          `;
          roleEditor = `
                <td class="py-2 px-3">
                    <form action="/admin/update-admin-role" method="post" class="flex items-center gap-2">
                        <input type="hidden" name="id" value="${a.id}" />
                        <select name="role" class="border rounded text-xs p-1">
                            <option value="normal" ${a.role === 'normal' ? 'selected' : ''}>Normal</option>
                            <option value="super" ${a.role === 'super' ? 'selected' : ''}>Super</option>
                        </select>
                        <button class="bg-blue-500 text-white px-2 py-1 rounded text-xs hover:bg-blue-600">Salvar</button>
                    </form>
                </td>
          `;
      }
  
      return `<tr class="border-b">
          <td class="py-2 px-3">${deleteForm}</td>
          <td class="py-2 px-3">${a.id}</td>
          <td class="py-2 px-3">${a.email}</td>
          ${roleEditor}
          <td class="py-2 px-3">${dayjs(a.created_at).format('DD/MM/YYYY')}</td>
      </tr>`
    }).join('');
    res.send(adminPage('Admins', `
      <div class="flex items-center justify-between mb-4">
          <h2 class="text-xl font-semibold">Administradores</h2>
          <a href="/admin/painel" class="link-brand underline text-sm">← Voltar para o Painel</a>
      </div>
      <div class="bg-white border rounded-xl p-6">
        <form method="post" action="/admin/invite" class="flex flex-wrap gap-2 mb-4 items-center">
          <input name="email" type="email" placeholder="email@exemplo.com" class="border rounded px-3 py-2 flex-1" required/>
          <button class="btn-brand px-4 py-2 rounded">Convidar</button>
        </form>
        <div class="overflow-x-auto">
          <table class="min-w-full text-sm">
            <thead class="bg-slate-100"><tr>
              <th class="px-3 py-2 text-left">Ação</th>
              <th class="px-3 py-2 text-left">ID</th>
              <th class="px-3 py-2 text-left">E-mail</th>
              <th class="px-3 py-2 text-left">Perfil</th>
              <th class="px-3 py-2 text-left">Criado</th>
            </tr></thead>
            <tbody>${tr || `<tr><td colspan="5" class="py-6 text-center text-slate-500">Sem admins</td></tr>`}</tbody>
          </table>
        </div>
      </div>
    `, adminData));
  });
  
  app.post('/admin/update-admin-role', requireSuper, async (req, res) => {
      try {
          const { id, role } = req.body;
          const adminData = verifyToken(req.cookies['admin_session']);
  
          if (!id || !['normal', 'super'].includes(role)) {
              return res.status(400).send('Dados inválidos.');
          }
  
          if (adminData && adminData.admin_id && id == adminData.admin_id) {
              return res.status(403).send('Você não pode alterar seu próprio perfil.');
          }
  
          const { rows } = await pool.query('SELECT email FROM admins WHERE id = $1', [id]);
          if (rows.length > 0 && rows[0].email === process.env.SUPER_ADMIN_EMAIL) {
              return res.status(403).send('O perfil do super administrador principal não pode ser alterado.');
          }
  
          await pool.query('UPDATE admins SET role = $1 WHERE id = $2', [role, id]);
          res.redirect('/admin/admins');
      } catch (e) {
          console.error(e);
          res.status(500).send('Erro ao atualizar perfil do administrador.');
      }
  });
  
  app.post('/admin/delete-admin', requireSuper, async (req, res) => {
      try {
          const { id } = req.body;
          const adminData = verifyToken(req.cookies['admin_session']);
  
          if (!id) {
              return res.status(400).send('ID do admin não fornecido.');
          }
          
          if (adminData && adminData.admin_id && id == adminData.admin_id) {
              return res.status(403).send('Você não pode se auto-excluir.');
          }
  
          const { rows } = await pool.query('SELECT role, email FROM admins WHERE id = $1', [id]);
          if (rows.length > 0 && (rows[0].role === 'super' || rows[0].email === process.env.SUPER_ADMIN_EMAIL)) {
              return res.status(403).send('Este administrador não pode ser excluído.');
          }
  
          await pool.query('DELETE FROM admins WHERE id = $1', [id]);
          res.redirect('/admin/admins');
  
      } catch (e) {
          console.error(e);
          res.status(500).send('Erro ao deletar o administrador.');
      }
  });
  
  app.post('/admin/invite', requireSuper, async (req,res)=>{
    const adminData = verifyToken(req.cookies['admin_session']);
    const email = (req.body.email||'').trim();
    const role = 'normal';
    const token = crypto.randomBytes(24).toString('hex');
    
    await pool.query('INSERT INTO admins(email, invite_token, invite_expires, role) VALUES($1,$2, NOW()+INTERVAL \'2 days\', $3) ON CONFLICT (email) DO UPDATE SET invite_token=$2, invite_expires=NOW()+INTERVAL \'2 days\'', [email, token, role]);
    
    const baseUrl = (process.env.APP_BASE_URL || '').replace(/\/$/, '');
    const link = `${baseUrl}/admin/first-access?token=${token}`;

    if (transporter) {
      try {
        await transporter.sendMail({ from: process.env.MAIL_FROM || 'no-reply@example.com', to: email, subject: 'Convite para Admin - Atitude Kids', html: `Finalize seu acesso: <a href="${link}">${link}</a>` });
      } catch (mailError) {
        console.error(`Falha ao enviar e-mail de convite para ${email}:`, mailError);
      }
    }
    res.send(adminPage('Convite enviado', `<p>Convite enviado (ou atualizado) para ${email}. Link: <span class="text-xs">${link}</span></p>`, adminData));
  });
  
  app.get('/admin/first-access', async (req,res)=>{
    const token = req.query.token;
    const { rows } = await pool.query('SELECT id,email FROM admins WHERE invite_token=$1 AND invite_expires>NOW() LIMIT 1', [token]);
    if (!rows.length) return res.send(adminPage('Convite inválido', '<p>Link inválido ou expirado.</p>'));
    res.send(adminPage('Definir senha do Admin', `
      <form method="post" action="/admin/first-access?token=${token}" class="max-w-sm mx-auto bg-white border rounded-xl p-6 space-y-3">
        <div>
          <label class="block text-sm">Senha</label>
          <div class="relative password-toggle-container">
            <input name="password" type="password" required class="w-full border rounded px-3 py-2 pr-10"/>
            <span class="password-toggle-icon absolute inset-y-0 right-0 pr-3 flex items-center cursor-pointer text-gray-500">
              <svg class="eye-icon h-5 w-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M2.036 12.322a1.012 1.012 0 010-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178z" /><path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /></svg>
              <svg class="eye-slash-icon hidden h-5 w-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M3.98 8.223A10.477 10.477 0 001.934 12C3.226 16.338 7.244 19.5 12 19.5c.993 0 1.953-.138 2.863-.395M6.228 6.228A10.45 10.45 0 0112 4.5c4.756 0 8.773 3.162 10.065 7.498a10.523 10.523 0 01-4.293 5.774M6.228 6.228L3 3m3.228 3.228l3.65 3.65m7.894 7.894L21 21m-3.228-3.228l-3.65-3.65m0 0a3 3 0 10-4.243-4.243m4.242 4.242L9.88 9.88" /></svg>
            </span>
          </div>
        </div>
        <button type="submit" class="btn-brand px-4 py-2 rounded">Salvar</button>
      </form>
    `));
  });
  
  app.post('/admin/first-access', async (req,res)=>{
    const token = req.query.token;
    const { rows } = await pool.query('SELECT id FROM admins WHERE invite_token=$1 AND invite_expires>NOW() LIMIT 1', [token]);
    if (!rows.length) return res.send(adminPage('Convite inválido', '<p>Link inválido ou expirado.</p>'));
    const hash = await bcrypt.hash(req.body.password || '', 10);
    await pool.query('UPDATE admins SET password_hash=$1, invite_token=NULL, invite_expires=NULL WHERE id=$2', [hash, rows[0].id]);
    res.send(adminPage('OK', '<p>Senha definida. <a href="/admin/login" class="link-brand underline">Entrar</a></p>'));
  });
  
  app.get('/admin/ver-pdf/:id', requireAdmin, setNoCacheHeaders, async (req, res) => {
    try {
      const { id } = req.params;
      const { rows } = await pool.query('SELECT pdf_path FROM cadastros WHERE id=$1', [id]);
  
      if (!rows.length || !rows[0].pdf_path) {
        return res.status(404).send('PDF não encontrado.');
      }
  
      const key = rows[0].pdf_path;
      const { data, error } = await supabase.storage
          .from(process.env.SUPABASE_BUCKET)
          .download(key);
  
      if (error) throw error;
      
      const buffer = Buffer.from(await data.arrayBuffer());
  
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Length', buffer.length);
      res.send(buffer);
  
    } catch (e) {
      console.error('Erro ao buscar PDF no Supabase:', e);
      res.status(500).send('Erro ao carregar o arquivo.');
    }
  });


// =====================
// Heartbeat de atividade (renova sessão a cada interação)
// =====================
app.post('/auth/ping', (req, res) => {
    const kind = (req.body && req.body.kind) || 'public';
    if (kind === 'admin') {
        const t = req.cookies['admin_session'];
        const data = verifyToken(t);
        if (data && !isIdle(data)) {
            const { name, token } = refreshActivityCookie('admin', data);
            res.cookie(name, token, { httpOnly: true, sameSite: 'lax', secure: true });
        }
    } else if (kind === 'vol') {
        const t = req.cookies['vol_session'];
        const data = verifyToken(t);
        if (data && !isIdle(data)) {
            const { name, token } = refreshActivityCookie('vol', data);
            res.cookie(name, token, { httpOnly: true, sameSite: 'lax', secure: true });
        }
    }
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.json({ ok: true });
});

// =====================
// Housekeeping & Cron Jobs
// =====================

app.post('/cron/enviar-lembretes-renovacao', async (req, res) => {
    // 1. Segurança: Verifica se a chave do cron job está correta
    if ((req.headers['x-cron-key'] || '') !== (process.env.CRON_KEY || '')) {
        return res.status(401).send('Unauthorized');
    }

    try {
        let emailsSent = 0;
        let pushSent = 0;
        let usersFlagged = 0;
        const reminderDays = [15, 7, 1]; // Envia lembretes 15, 7 e 1 dia antes

        for (const day of reminderDays) {
            const { rows: usersToRemind } = await pool.query(
                `SELECT id, nome, email, issued_at FROM cadastros 
         WHERE status = 'apto' AND (issued_at + INTERVAL '6 months')::date = (NOW() + INTERVAL '${day} days')::date`
            );

            for (const user of usersToRemind) {
                const subject = `Lembrete: Atualize seu CAC no Atitude Kids`;
                const dueDate = dayjs(user.issued_at).add(6, 'months').format('DD/MM/YYYY');
                
                const htmlBody = `
                  <p>Olá, ${user.nome}!</p>
                  <p>Esperamos que esta mensagem o encontre bem.</p>
                  <p>Para continuarmos em conformidade com as boas práticas de segurança e com a legislação vigente, nosso ministério realiza a renovação da Certidão de Antecedentes Criminais (CAC) de todos os servos a cada 6 meses.</p>
                  <p>A data de emissão do seu último documento completará 6 meses em <strong>${dueDate}</strong>. Para nos ajudar a manter seu cadastro atualizado, por favor, acesse seu painel em nosso site e envie uma certidão recém-emitida.</p>
                  <p><a href="${process.env.APP_BASE_URL || ''}/login">Acessar meu painel</a></p>
                  <p>Agradecemos imensamente seu tempo, seu serviço e seu cuidado contínuo com a segurança de nossas crianças.</p>
                  <p>Um abraço,<br>Liderança Atitude Kids</p>
                `;
                
                await sendEmail(user.email, subject, htmlBody);
                emailsSent++;

                await sendPushNotification(user.id, {
                    title: `Lembrete de Renovação - Atitude Kids`,
                    body: `Sua certidão precisa ser renovada até ${dueDate}. Clique para atualizar.`
                });
                pushSent++;
            }
        }

        const { rows: expiredUsersNeedingReminder } = await pool.query(
            `SELECT id, nome, email, expires_at
             FROM cadastros
             WHERE status = 'em_revisao'
               AND expires_at IS NOT NULL
               AND expires_at::date <= NOW()::date
               AND ((NOW()::date - expires_at::date) % 7) = 0`
        );

        for (const expiredUser of expiredUsersNeedingReminder) {
            const expiredDate = dayjs(expiredUser.expires_at).format('DD/MM/YYYY');

            const weeklyHtml = `
              <p>Olá, ${expiredUser.nome}!</p>
              <p>Identificamos que a sua Certidão de Antecedentes Criminais venceu em <strong>${expiredDate}</strong> e ainda precisamos do novo documento para manter seu cadastro regularizado.</p>
              <p>Por favor, acesse o painel do servo e envie uma certidão renovada para regularizar sua situação.</p>
              <p><a href="${process.env.APP_BASE_URL || ''}/login">Acessar meu painel</a></p>
              <p>Assim que recebermos o novo PDF, seu status volta ao normal automaticamente.</p>
              <p>Obrigado pelo cuidado,<br>Liderança Atitude Kids</p>
            `;

            await sendEmail(expiredUser.email, 'CAC vencido - regularize seu cadastro', weeklyHtml);
            emailsSent++;

            await sendPushNotification(expiredUser.id, {
                title: `CAC vencido - atualização pendente`,
                body: `Seu documento venceu em ${expiredDate}. Envie um novo PDF para liberar seu cadastro.`
            });
            pushSent++;
        }

        const { rows: usersToFlag } = await pool.query(
            `SELECT id FROM cadastros WHERE status = 'apto' AND expires_at <= NOW()`
        );

        if (usersToFlag.length > 0) {
            const idsToFlag = usersToFlag.map(u => u.id);
            
            // ##################################################################
            // ## INÍCIO DA ALTERAÇÃO: Mudar status para 'em_revisao'
            // ##################################################################
            
            await pool.query(
                `UPDATE cadastros SET status = 'em_revisao' WHERE id = ANY($1::int[])`,
                [idsToFlag]
            );
            
            // ##################################################################
            // ## FIM DA ALTERAÇÃO
            // ##################################################################
            
            usersFlagged = idsToFlag.length;
        }

        res.json({
            ok: true,
            message: `Rotina de lembretes executada.`,
            emailsSent,
            pushSent,
            usersFlagged,
        });

    } catch (e) {
        console.error('Erro na rotina de lembretes de renovação:', e);
        res.status(500).send('Erro ao executar a rotina de lembretes.');
    }
});

app.post('/cron/housekeeping', async (req, res) => {
    if ((req.headers['x-cron-key'] || '') !== (process.env.CRON_KEY || '')) return res.status(401).send('unauthorized');
    try {
        const { rows } = await pool.query(`SELECT id, pdf_path FROM cadastros WHERE expires_at IS NOT NULL AND expires_at < NOW() - INTERVAL '180 days'`);
        if (rows.length > 0) {
            const pathsToDelete = rows.map(r => r.pdf_path).filter(Boolean);
            if (pathsToDelete.length > 0) {
                await supabase.storage.from(process.env.SUPABASE_BUCKET).remove(pathsToDelete);
            }
        }
        await pool.query(`DELETE FROM cadastros WHERE expires_at IS NOT NULL AND expires_at < NOW() - INTERVAL '180 days'`);
        res.send(`Limpou ${rows.length} registros antigos.`);
    } catch (e) {
        console.error(e);
        res.status(500).send('erro housekeeping');
    }
});

// =====================
// Erros
// =====================
app.use((err, req, res, next) => {
    if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).send(page('Erro no Upload', '<p class="text-red-600 font-semibold">O arquivo enviado é muito grande. O tamanho máximo permitido é de 2MB.</p>'));
        }
        return res.status(400).send(page('Erro no Upload', `<p>Ocorreu um erro durante o upload do arquivo: ${err.message}</p>`));
    }

    console.error(err);
    res.status(500).send(page('Erro', '<p>Ocorreu um erro inesperado no servidor. Por favor, tente novamente.</p>'));
});

// ======================
// Start server
// ======================
const startServer = async () => {
    try {
        console.log('Testando conexão com o banco de dados...');
        const client = await pool.connect();
        console.log('✅ Conexão com o banco de dados bem-sucedida.');
        client.release();

        app.listen(process.env.PORT || 3000, () => {
            console.log(`🚀 Servidor on-line na porta ${process.env.PORT || 3000}`);
        });

    } catch (error) {
        console.error('❌ Não foi possível conectar ao banco de dados ao iniciar.', error);
        process.exit(1);
    }
};

startServer();
