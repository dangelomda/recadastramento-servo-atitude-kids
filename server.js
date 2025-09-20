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

const ORG = process.env.ORG_NOME || 'Recadastramento Servo Atitude Kids';
const BRAND = {
  primary: process.env.BRAND_PRIMARY || '#4f46e5',
  accent: process.env.BRAND_ACCENT || '#22c55e',
  logo: process.env.BRAND_LOGO_PATH || '/public/logo.svg',
};

const app = express();
app.use('/public', express.static(path.join(__dirname, 'public')));
app.use('/favicon.svg', express.static(path.join(__dirname, 'public', 'favicon.svg')));

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

// Middlewares
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 150 }));
app.set('trust proxy', 1);

// Upload: 2 MB em memória
const upload = multer({ limits: { fileSize: 2 * 1024 * 1024 } });

// Helpers
function signToken(payload, secretEnv = 'SESSION_SECRET') {
  const secret = process.env[secretEnv] || 'dev-secret';
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', secret).update(`${header}.${body}`).digest('base64url');
  return `${header}.${body}.${sig}`;
}
function verifyToken(token, secretEnv = 'SESSION_SECRET') {
  const secret = process.env[secretEnv] || 'dev-secret';
  const [h, b, s] = (token || '').split('.');
  if (!h || !b || !s) return null;
  const sig = crypto.createHmac('sha256', secret).update(`${h}.${b}`).digest('base64url');
  if (sig !== s) return null;
  try { return JSON.parse(Buffer.from(b, 'base64url').toString()); } catch { return null; }
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
  if (data && data.role && data.role.startsWith('admin')) return next();
  return res.redirect('/admin/login');
}
function requireSuper(req,res,next){
  const t=req.cookies['admin_session']; const d=verifyToken(t);
  if (d && d.role==='admin:super') return next();
  return res.status(403).send('Somente super admin.');
}
function requireVolunteer(req, res, next) {
  const t = req.cookies['vol_session'];
  const data = verifyToken(t);
  if (data && data.volunteer_id) { req.vol = data; return next(); }
  return res.redirect('/login');
}
function badge(status, cacResult) {
  if (status === 'inapto') return '🔴 Inapto';
  if (status === 'atencao') return '🟡 Atenção';
  if (status === 'apto' && cacResult === 'nada_consta') return '✅ Apto';
  if (status === 'apto') return '⚠️ Apto (Revisar)';
  return '⚪ Em revisão';
}

async function extractFromPdf(pdfBuffer) {
  const pdfData = await pdfParse(pdfBuffer);
  const text = (pdfData.text || '').toUpperCase().replace(/\s+/g, ' ');
  const numMatch = text.match(/N[º°:]\s*(\d{6,})/) || text.match(/CRIMINAIS N° (\d+)/);
  const datePatterns = [
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
  const expires_at = (issued_at && issued_at.isValid()) ? issued_at.add(90, 'day') : null;
  let cac_result = 'desconhecido';
  if (text.includes('NÃO CONSTA') || text.includes('NADA CONSTA')) {
    cac_result = 'nada_consta';
  }
  return { cert_number, issued_at, expires_at, cac_result, pdf_cpf };
}

const page = (title, bodyHtml) => `<!doctype html>
<html lang="pt-BR">
<head>
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
</head>
<body class="bg-slate-50 text-slate-800">
<header class="bg-white border-b sticky top-0 z-10">
  <div class="max-w-5xl mx-auto px-4 py-4 flex items-center justify-between">
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
<main class="max-w-5xl mx-auto px-4 py-8">
${bodyHtml}
</main>
<footer class="text-center text-xs text-slate-500 py-8">© ${new Date().getFullYear()} ${ORG}</footer>

<script>
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
</script>
</body>
</html>`;

const adminPage = (title, bodyHtml) => `<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>${title}</title>
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<script src="https://cdn.tailwindcss.com"></script>
<style>
  :root{ --brand:${BRAND.primary}; --accent:${BRAND.accent}; }
  .btn-brand{ background: var(--brand); color:#fff; }
  .btn-brand:hover{ filter: brightness(0.95); }
  .link-brand{ color: var(--brand); }
</style>
</head>
<body class="bg-slate-50 text-slate-800">
<header class="bg-white border-b sticky top-0 z-10">
  <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4 flex items-center justify-between">
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
<main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
${bodyHtml}
</main>
<footer class="text-center text-xs text-slate-500 py-8">© ${new Date().getFullYear()} ${ORG}</footer>

<script>
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
</script>
</body>
</html>`;

// ===== Rotas Públicas =====
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

// ===== Cadastro de voluntário =====
app.get('/cadastro', (_req, res) => {
  res.type('html').send(page('Cadastro', `
    <div class="max-w-xl mx-auto bg-white border rounded-xl p-6">
      <h2 class="text-2xl font-semibold mb-4">Crie sua conta</h2>
      <form method="post" action="/cadastro" enctype="multipart/form-data">
        <div class="space-y-4">
          <div><label class="block text-sm mb-1">Nome completo</label><input name="nome" required class="w-full border rounded px-3 py-2"/></div>
          <div><label class="block text-sm mb-1">CPF</label><input name="cpf" required placeholder="000.000.000-00" class="w-full border rounded px-3 py-2"/></div>
          <div><label class="block text-sm mb-1">E-mail</label><input name="email" type="email" required class="w-full border rounded px-3 py-2"/></div>
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
          <div class="flex items-start gap-2"><input type="checkbox" name="consent" required class="mt-1"><label class="text-sm">Li e aceito o <a href="/termo-lgpd" target="_blank" class="link-brand underline">termo de consentimento</a>.</label></div>
          <button type="submit" class="btn-brand px-5 py-2.5 rounded w-full">Cadastrar</button>
        </div>
      </form>
    </div>
  `));
});

app.post('/cadastro', upload.single('cac_pdf'), async (req, res, next) => {
  try {
    const { nome, cpf, email, password, consent } = req.body;
    const cpfClean = cpf.replace(/\D/g, '');
    const emailClean = email.trim().toLowerCase();

    const { rows: existingUsers } = await pool.query(
      'SELECT id FROM cadastros WHERE cpf = $1 OR email = $2',
      [cpfClean, emailClean]
    );

    if (existingUsers.length > 0) {
      return res.status(409).send(page('Erro', '<p class="text-red-600 font-semibold">CPF ou E-mail já cadastrado. Se você já tem uma conta, por favor, <a href="/login" class="link-brand underline">faça o login</a>.</p>'));
    }

    if (!nome || !cpf || !email || !password || consent !== 'on' || !req.file)
      return res.status(400).send(page('Erro', '<p>Preencha todos os campos, aceite o termo e anexe o PDF.</p>'));
    
    if (!cpfValidator.isValid(cpfClean))
      return res.status(400).send(page('Erro', '<p>CPF inválido.</p>'));

    if (req.file.mimetype !== 'application/pdf')
      return res.status(400).send(page('Erro', '<p>Envie um PDF válido.</p>'));
    
    const password_hash = await bcrypt.hash(password, 10);
    const pdfBuffer = req.file.buffer;
    
    const { cert_number, issued_at, expires_at, cac_result, pdf_cpf } = await extractFromPdf(pdfBuffer);

    if (!cert_number || !issued_at || !issued_at.isValid()) {
      return res.status(400).send(page('Erro', '<p class="text-red-600 font-semibold">O arquivo enviado não parece ser uma Certidão de Antecedentes Criminais válida. Por favor, emita o documento correto no site do Gov.br e tente novamente.</p>'));
    }

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
        status = 'inapto';
      } else if (cac_result === 'nada_consta') {
        if (expires_at.diff(now, 'day') <= 15) {
          status = 'atencao';
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
    const insert = `
      INSERT INTO cadastros
      (nome, cpf, email, password_hash, cert_number, issued_at, expires_at, status, pdf_path, pdf_sha256, cac_result, consent_signed_at, created_at, updated_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NOW(),NOW(),NOW()) RETURNING id
    `;
    const vals = [nome.trim(), cpfClean, emailClean, password_hash, cert_number, issued_at.toISOString(), expires_at.toISOString(), status, key, pdf_sha256, cac_result];
    const { rows } = await pool.query(insert, vals);
    const token = signToken({ volunteer_id: rows[0].id, email: emailClean });
    res.cookie('vol_session', token, { httpOnly: true, sameSite: 'lax', secure: true });
    res.send(page('Conta criada', `<p>Cadastro concluído! Protocolo ${rows[0].id}. <a href="/meu/painel" class="link-brand underline">Ir para meu painel</a></p>`));
  } catch (e) {
    next(e);
  }
});

// ===== Login voluntário =====
app.get('/login', (_req, res) => {
  // CORREÇÃO: Limpa qualquer sessão ativa ao chegar na tela de login
  res.clearCookie('vol_session');
  res.clearCookie('admin_session');
  
  res.send(page('Login', `
    <div class="max-w-sm mx-auto bg-white border rounded-xl p-6">
      <h2 class="text-xl font-semibold mb-4">Login do voluntário</h2>
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

  const token = signToken({ volunteer_id: rows[0].id, email: email.trim() });
  res.cookie('vol_session', token, { httpOnly: true, sameSite: 'lax', secure: true });
  await pool.query('UPDATE cadastros SET last_login_at=NOW() WHERE id=$1', [rows[0].id]);
  res.redirect('/meu/painel');
});

// ===== Painel do voluntário =====
app.get('/meu/painel', requireVolunteer, setNoCacheHeaders, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM cadastros WHERE id=$1', [req.vol.volunteer_id]);
  const r = rows[0];
  const issued = r.issued_at ? dayjs(r.issued_at).format('DD/MM/YYYY') : '-';
  const exp = r.expires_at ? dayjs(r.expires_at).format('DD/MM/YYYY') : '-';

  const updateFormHtml = (r.status === 'apto' || r.status === 'em_revisao')
    ? `<div class="mt-6 pt-6 border-t">
        <h3 class="font-semibold mb-2">Atualizar dados</h3>
        <form method="post" action="/meu/atualizar" enctype="multipart/form-data" class="space-y-3">
          <div><label class="block text-sm">Novo e-mail (opcional)</label><input name="email" type="email" class="w-full border rounded px-3 py-2"/></div>
          <div><label class="block text-sm">Nova CAC (PDF até 2MB, opcional)</label><input type="file" name="cac_pdf" accept="application/pdf" class="w-full"/></div>
          <div class="flex items-start gap-2"><input type="checkbox" name="consent" required class="mt-1"><label class="text-sm">Confirmo novamente o <a href="/termo-lgpd" class="link-brand underline" target="_blank">termo de consentimento</a>.</label></div>
          <button type="submit" class="btn-brand px-4 py-2 rounded">Salvar</button>
        </form>
      </div>`
    : `<div class="mt-6 pt-6 border-t">
          <h3 class="font-semibold mb-2">Atualização Bloqueada</h3>
          <div class="text-sm text-amber-800 bg-amber-100 p-4 rounded-lg">
            <p>Seu cadastro foi marcado como <strong>${badge(r.status, r.cac_result)}</strong> pela administração.</p>
            <p class="mt-2">Para fazer alterações ou enviar um novo documento, por favor, entre em contato com a liderança do ministério.</p>
          </div>
        </div>`;

  res.send(page('Meu Painel', `
    <div class="max-w-2xl mx-auto bg-white border rounded-xl p-6">
      <h2 class="text-2xl font-semibold mb-2">Olá, ${r.nome}</h2>
      <p class="text-sm mb-4">Status: ${badge(r.status, r.cac_result)}</p>
      <ul class="text-sm space-y-1 mb-4">
        <li><strong>E-mail:</strong> ${r.email}</li>
        <li><strong>CPF:</strong> ${r.cpf}</li>
        <li><strong>Nº certidão:</strong> ${r.cert_number || '-'}</li>
        <li><strong>Emitida em:</strong> ${issued}</li>
        <li><strong>Válida até:</strong> ${exp}</li>
      </ul>
      
      ${r.pdf_path ? `<p><a href="/meu/ver-pdf" target="_blank" class="text-sm link-brand underline">Visualizar CAC enviado</a></p>` : ''}
      
      ${updateFormHtml}

      <p class="mt-6 text-sm"><a href="/logout" class="link-brand underline">Sair</a></p>
    </div>
  `));
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

app.get('/logout', (req,res)=>{  
  res.clearCookie('vol_session');  
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

    if (currentStatus === 'inapto' || currentStatus === 'atencao') {
      return res.status(403).send(page('Atualização Bloqueada', '<p class="text-red-600 font-semibold">Sua conta está com um status que não permite atualizações automáticas. Por favor, entre em contato com a administração.</p>'));
    }

    if (req.body.consent !== 'on') return res.status(400).send(page('Erro', '<p>Você precisa confirmar o termo de consentimento.</p>'));

    const updates = [];
    const params = [];
    let idx = 1;

    if (req.body.email) { 
      updates.push(`email=$${idx++}`); 
      params.push(req.body.email.trim().toLowerCase()); 
    }

    if (req.file) {
      if (req.file.mimetype !== 'application/pdf') return res.status(400).send(page('Erro', '<p>Envie um PDF válido.</p>'));
      
      const pdfBuffer = req.file.buffer;
      const { cert_number, issued_at, expires_at, cac_result, pdf_cpf } = await extractFromPdf(pdfBuffer);
      
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

      let newStatus = 'em_revisao';
      if (issued_at && expires_at && issued_at.isValid()) {
        const now = dayjs();
        if (now.isAfter(expires_at)) {
          newStatus = 'inapto';
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

// ===== Reset de senha voluntário =====
app.get('/forgot', (_req,res)=> {
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

app.post('/forgot', async (req,res)=> {
  const email = (req.body.email||'').trim().toLowerCase();
  const { rows } = await pool.query('SELECT id FROM cadastros WHERE email=$1 LIMIT 1', [email]);
  if (!rows.length) return res.send(page('OK', '<p>Se existir conta com este e-mail, enviaremos um link para recuperação de senha.</p>'));

  const token = crypto.randomBytes(24).toString('hex');
  await pool.query('UPDATE cadastros SET reset_token=$1, reset_expires=NOW()+INTERVAL \'1 day\' WHERE id=$2', [token, rows[0].id]);
  const link = `${process.env.APP_BASE_URL || ''}/reset?token=${token}`;

  if (transporter) {
    try {
      await transporter.sendMail({ from: process.env.MAIL_FROM || 'no-reply@example.com', to: email,
        subject: 'Redefinição de senha', html: `Clique aqui para redefinir sua senha: <a href="${link}">${link}</a>` });
    } catch (mailError) {
        console.error("Erro ao enviar e-mail de recuperação:", mailError);
    }
  }

  res.send(page('OK', `<p>Se existir uma conta com o e-mail informado, um link para recuperação de senha foi enviado. Por favor, verifique sua caixa de entrada e spam.</p>`));
});

app.get('/reset', async (req,res)=> {
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

app.post('/reset', async (req,res)=> {
  const token = req.query.token;
  const { rows } = await pool.query('SELECT id FROM cadastros WHERE reset_token=$1 AND reset_expires>NOW() LIMIT 1', [token]);
  if (!rows.length) return res.send(page('Reset', '<p>Link inválido ou expirado.</p>'));
  const hash = await bcrypt.hash(req.body.password || '', 10);
  await pool.query('UPDATE cadastros SET password_hash=$1, reset_token=NULL, reset_expires=NULL WHERE id=$2', [hash, rows[0].id]);
  res.send(page('OK', '<p>Senha atualizada com sucesso. <a href="/login" class="link-brand underline">Clique aqui para entrar</a>.</p>'));
});

// ===== Admin =====
app.get('/admin/login', (_req, res) => {
  // CORREÇÃO: Limpa qualquer sessão ativa ao chegar na tela de login do admin
  res.clearCookie('vol_session');
  res.clearCookie('admin_session');

  res.send(adminPage('Login Admin', `
    <div class="max-w-sm mx-auto bg-white border rounded-xl p-6">
      <h2 class="text-xl font-semibold mb-4">Acesso do administrador</h2>
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

// ===== Reset de senha Admin (NOVA FUNCIONALIDADE) =====
app.get('/admin/forgot', (_req, res) => {
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
    
    // Não funciona para o super admin definido no .env, o que é esperado.
    if (!rows.length) {
      return res.send(adminPage('OK', '<p>Se existir uma conta de administrador com este e-mail, enviaremos um link para recuperação de senha.</p>'));
    }

    const token = crypto.randomBytes(24).toString('hex');
    await pool.query('UPDATE admins SET reset_token=$1, reset_expires=NOW()+INTERVAL \'1 day\' WHERE id=$2', [token, rows[0].id]);
    const link = `${process.env.APP_BASE_URL || ''}/admin/reset?token=${token}`;

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

app.get('/admin/reset', async (req, res, next) => {
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
  res.clearCookie('admin_session');
  res.redirect('/admin/login');
});

app.get('/admin/painel', requireAdmin, setNoCacheHeaders, async (_req,res)=>{
  const { rows } = await pool.query('SELECT id,nome,cpf,email,cert_number,issued_at,expires_at,status,cac_result,pdf_path FROM cadastros ORDER BY created_at DESC LIMIT 500');
  const tr = rows.map(r=>{
    const issued = r.issued_at ? dayjs(r.issued_at).format('DD/MM/YYYY') : '-';
    const exp = r.expires_at ? dayjs(r.expires_at).format('DD/MM/YYYY') : '-';
    const linkPf = r.cert_number ? `https://servicos.pf.gov.br/epol-sinic-publico/validar-cac?numero=${r.cert_number}` : '#';
    const acaoValidar = r.cert_number ? `<a target="_blank" href="${linkPf}" class="link-brand underline">Validar na PF</a>` : '-';
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
      <td class="py-2 px-3">${r.cpf}</td>
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
  res.send(adminPage('Painel Admin', `
    <div class="flex items-center justify-between mb-4">
      <h2 class="text-2xl font-semibold">Cadastros</h2>
      <a href="/admin/logout" class="link-brand underline text-sm">Sair</a>
    </div>
    <div class="overflow-x-auto bg-white border rounded-xl mb-6">
      <table class="min-w-full text-sm">
        <thead class="bg-slate-100"><tr>
            <th class="px-3 py-2 text-left">Ação</th>
            <th class="px-3 py-2 text-left">ID</th>
            <th class="px-3 py-2 text-left">Nome Completo</th>
            <th class="px-3 py-2 text-left">CPF</th>
            <th class="px-3 py-2 text-left">E-mail</th>
            <th class="px-3 py-2 text-left">Certidão</th>
            <th class="px-3 py-2 text-left">Emissão</th>
            <th class="px-3 py-2 text-left">Validade</th>
            <th class="px-3 py-2 text-left">Status Badge</th>
            <th class="px-3 py-2 text-left">Mudar Status</th>
            <th class="px-3 py-2 text-left">Validar</th>
            <th class="px-3 py-2 text-left">PDF</th>
        </tr></thead>
        <tbody>${tr || `<tr><td colspan="12" class="py-6 text-center text-slate-500">Sem registros</td></tr>`}</tbody>
      </table>
    </div>
    <a href="/admin/admins" class="btn-brand px-4 py-2 rounded">Gerenciar Admins</a>
  `));
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

app.get('/admin/admins', requireSuper, async (req,res)=>{
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
    `));
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
    const email = (req.body.email||'').trim();
    const role = 'normal';
    const token = crypto.randomBytes(24).toString('hex');
    
    await pool.query('INSERT INTO admins(email, invite_token, invite_expires, role) VALUES($1,$2, NOW()+INTERVAL \'2 days\', $3) ON CONFLICT (email) DO UPDATE SET invite_token=$2, invite_expires=NOW()+INTERVAL \'2 days\'', [email, token, role]);
    
    const link = `${process.env.APP_BASE_URL || ''}/admin/first-access?token=${token}`;
    if (transporter) {
      await transporter.sendMail({ from: process.env.MAIL_FROM || 'no-reply@example.com', to: email, subject: 'Convite para Admin - Atitude Kids', html: `Finalize seu acesso: <a href="${link}">${link}</a>` });
    }
    res.send(adminPage('Convite enviado', `<p>Convite enviado (ou atualizado) para ${email}. Link: <span class="text-xs">${link}</span></p>`));
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
        <button class="btn-brand px-4 py-2 rounded">Salvar</button>
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
  
  app.get('/admin/ver-pdf/:id', requireAdmin, async (req, res) => {
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

// Start server
app.listen(process.env.PORT || 3000, () => console.log(`On-line na porta ${process.env.PORT || 3000}`));