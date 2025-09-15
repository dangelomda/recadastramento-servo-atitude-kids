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
const { URL } = require('url'); // Importa a classe URL

const ORG = process.env.ORG_NOME || 'Recadastramento Servo Atitude Kids';
const BRAND = {
  primary: process.env.BRAND_PRIMARY || '#4f46e5',
  accent: process.env.BRAND_ACCENT || '#22c55e',
  logo: process.env.BRAND_LOGO_PATH || '/logo.svg',
};

const app = express();
app.use('/public', express.static(path.join(__dirname, 'public')));
app.use('/favicon.svg', express.static(path.join(__dirname, 'public', 'favicon.svg')));

// Infra
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSL === 'require' ? { rejectUnauthorized: false } : false,
  // ✅ CORREÇÃO PARA AMBIENTES DE HOSPEDAGEM (RENDER): Força a resolução para IPv4
  host: new URL(process.env.DATABASE_URL).hostname,
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

  const cert_number = numMatch ? numMatch[1] : null;
  const expires_at = (issued_at && issued_at.isValid()) ? issued_at.add(90, 'day') : null;
  
  let cac_result = 'desconhecido';
  if (text.includes('NÃO CONSTA') || text.includes('NADA CONSTA')) {
    cac_result = 'nada_consta';
  }

  return { cert_number, issued_at, expires_at, cac_result };
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
</style>
</head>
<body class="bg-slate-50 text-slate-800">
<header class="bg-white border-b">
  <div class="max-w-5xl mx-auto px-4 py-4 flex items-center justify-between">
    <div class="flex items-center gap-3">
      <img src="${BRAND.logo}" alt="logo" class="h-8 w-auto" onerror="this.src='/public/logo.svg'">
      <div class="text-lg font-semibold">${ORG}</div>
    </div>
    <nav class="text-sm">
      <a href="/" class="mr-4">Início</a>
      <a href="/cadastro" class="mr-4">Cadastro</a>
      <a href="/login">Login</a>
      <a href="/admin/login" class="ml-4 pl-4 border-l border-slate-200">Admin</a>
    </nav>
  </div>
</header>
<main class="max-w-5xl mx-auto px-4 py-8">
${bodyHtml}
</main>
<footer class="text-center text-xs text-slate-500 py-8">© ${new Date().getFullYear()} ${ORG}</footer>
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
<header class="bg-white border-b">
  <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4 flex items-center justify-between">
    <div class="flex items-center gap-3">
      <img src="${BRAND.logo}" alt="logo" class="h-8 w-auto" onerror="this.src='/public/logo.svg'">
      <div class="text-lg font-semibold">${ORG}</div>
    </div>
    <nav class="text-sm">
      <a href="/" class="mr-4">Início</a>
      <a href="/cadastro" class="mr-4">Cadastro</a>
      <a href="/login">Login</a>
      <a href="/admin/login" class="ml-4 pl-4 border-l border-slate-200">Admin</a>
    </nav>
  </div>
</header>
<main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
${bodyHtml}
</main>
<footer class="text-center text-xs text-slate-500 py-8">© ${new Date().getFullYear()} ${ORG}</footer>
</body>
</html>`;

// ===== Rotas Públicas =====
app.get('/', (_req, res) => {
  res.type('html').send(page('Início', `
    <div class="grid md:grid-cols-2 gap-8 items-center">
      <div>
        <h1 class="text-3xl font-bold mb-4">Recadastramento Servo Atitude Kids</h1>
        <p class="mb-4">Para servir no ministério infantil, é necessário anexar a <strong>Certidão de Antecedentes Criminais (CAC)</strong>, aceitar o termo de privacidade (LGPD) e criar uma senha.</p>
        <a href="/cadastro" class="btn-brand px-5 py-3 rounded-lg">Começar cadastro</a>
      </div>
      <div class="bg-white border rounded-xl p-6">
        <ul class="space-y-2 text-sm">
          <li>✔ Conta com senha e recuperação</li>
          <li>✔ Upload obrigatório da CAC (PDF)</li>
          <li>✔ Extração automática (nº, emissão, validade)</li>
          <li>✔ Semáforo de status (verde/amarelo/vermelho)</li>
          <li>✔ Painel Admin para acompanhamento</li>
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
      <form method="post" action="/cadastro" enctype="multipart/form-data" class="space-y-4">
        <div><label class="block text-sm mb-1">Nome completo</label><input name="nome" required class="w-full border rounded px-3 py-2"/></div>
        <div><label class="block text-sm mb-1">CPF</label><input name="cpf" required placeholder="000.000.000-00" class="w-full border rounded px-3 py-2"/></div>
        <div><label class="block text-sm mb-1">E-mail</label><input name="email" type="email" required class="w-full border rounded px-3 py-2"/></div>
        <div><label class="block text-sm mb-1">Senha</label><input name="password" type="password" required class="w-full border rounded px-3 py-2"/></div>
        <div><label class="block text-sm mb-1">CAC (PDF até 2MB)</label><input type="file" name="cac_pdf" accept="application/pdf" required class="w-full"/></div>
        <div class="flex items-start gap-2"><input type="checkbox" name="consent" required class="mt-1"><label class="text-sm">Li e aceito o <a href="/termo-lgpd" target="_blank" class="link-brand underline">termo de consentimento</a>.</label></div>
        <button class="btn-brand px-5 py-2.5 rounded">Cadastrar</button>
      </form>
    </div>
  `));
});

app.post('/cadastro', upload.single('cac_pdf'), async (req, res) => {
  try {
    const { nome, cpf, email, password, consent } = req.body;
    if (!nome || !cpf || !email || !password || consent !== 'on' || !req.file)
      return res.status(400).send(page('Erro', '<p>Preencha todos os campos, aceite o termo e anexe o PDF.</p>'));

    const cpfClean = cpf.replace(/\D/g, '');
    if (!cpfValidator.isValid(cpfClean))
      return res.status(400).send(page('Erro', '<p>CPF inválido.</p>'));

    if (req.file.mimetype !== 'application/pdf')
      return res.status(400).send(page('Erro', '<p>Envie um PDF válido.</p>'));

    const password_hash = await bcrypt.hash(password, 10);
    const pdfBuffer = req.file.buffer;
    const pdf_sha256 = crypto.createHash('sha256').update(pdfBuffer).digest('hex');
    
    const { cert_number, issued_at, expires_at, cac_result } = await extractFromPdf(pdfBuffer);

    let status = 'em_revisao';
    if (issued_at && expires_at && issued_at.isValid()) {
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

    const key = `cac/${Date.now()}_${cert_number || 'sem-numero'}.pdf`;
    
    const { error: uploadError } = await supabase.storage
        .from(process.env.SUPABASE_BUCKET)
        .upload(key, pdfBuffer, { contentType: 'application/pdf', upsert: true });

    if (uploadError) throw uploadError;

    const insert = `
      INSERT INTO cadastros
      (nome, cpf, email, password_hash, cert_number, issued_at, expires_at, status, pdf_path, pdf_sha256, cac_result, consent_signed_at, created_at, updated_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NOW(),NOW(),NOW()) RETURNING id
    `;
    const vals = [nome.trim(), cpfClean, email.trim(), password_hash, cert_number, (issued_at && issued_at.isValid()) ? issued_at.toISOString() : null, (expires_at && expires_at.isValid()) ? expires_at.toISOString() : null, status, key, pdf_sha256, cac_result];
    const { rows } = await pool.query(insert, vals);

    const token = signToken({ volunteer_id: rows[0].id, email: email.trim() });
    res.cookie('vol_session', token, { httpOnly: true, sameSite: 'lax', secure: true });

    res.send(page('Conta criada', `<p>Cadastro concluído! Protocolo ${rows[0].id}. <a href="/meu/painel" class="link-brand underline">Ir para meu painel</a></p>`));
  } catch (e) {
    console.error(e);
    res.status(500).send(page('Erro', '<p>Erro ao processar cadastro.</p>'));
  }
});

// ===== Login voluntário =====
app.get('/login', (_req, res) => {
  res.send(page('Login', `
    <div class="max-w-sm mx-auto bg-white border rounded-xl p-6">
      <h2 class="text-xl font-semibold mb-4">Login do voluntário</h2>
      <form method="post" action="/login" class="space-y-3">
        <div><label class="block text-sm">E-mail</label><input name="email" type="email" class="w-full border rounded px-3 py-2" required/></div>
        <div><label class="block text-sm">Senha</label><input name="password" type="password" class="w-full border rounded px-3 py-2" required/></div>
        <button class="btn-brand px-4 py-2 rounded">Entrar</button>
      </form>
      <p class="text-sm mt-2"><a href="/forgot" class="link-brand underline">Esqueci minha senha</a></p>
    </div>
  `));
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body || {};
  const { rows } = await pool.query('SELECT id,password_hash FROM cadastros WHERE email=$1 LIMIT 1', [email?.trim()]);
  if (!rows.length || !(await bcrypt.compare(password || '', rows[0].password_hash || '')))
    return res.send(page('Login', '<p>Credenciais inválidas.</p>'));

  const token = signToken({ volunteer_id: rows[0].id, email: email.trim() });
  res.cookie('vol_session', token, { httpOnly: true, sameSite: 'lax', secure: true });
  await pool.query('UPDATE cadastros SET last_login_at=NOW() WHERE id=$1', [rows[0].id]);
  res.redirect('/meu/painel');
});
// ===== Painel do voluntário =====
app.get('/meu/painel', requireVolunteer, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM cadastros WHERE id=$1', [req.vol.volunteer_id]);
  const r = rows[0];
  const issued = r.issued_at ? dayjs(r.issued_at).format('DD/MM/YYYY') : '-';
  const exp = r.expires_at ? dayjs(r.expires_at).format('DD/MM/YYYY') : '-';

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
      <h3 class="font-semibold mb-2">Atualizar dados</h3>
      <form method="post" action="/meu/atualizar" enctype="multipart/form-data" class="space-y-3">
        <div><label class="block text-sm">Novo e-mail (opcional)</label><input name="email" type="email" class="w-full border rounded px-3 py-2"/></div>
        <div><label class="block text-sm">Nova CAC (PDF até 2MB, opcional)</label><input type="file" name="cac_pdf" accept="application/pdf" class="w-full"/></div>
        <div class="flex items-start gap-2"><input type="checkbox" name="consent" required class="mt-1"><label class="text-sm">Confirmo novamente o <a href="/termo-lgpd" class="link-brand underline" target="_blank">termo de consentimento</a>.</label></div>
        <button class="btn-brand px-4 py-2 rounded">Salvar</button>
      </form>
      <p class="mt-4 text-sm"><a href="/logout" class="link-brand underline">Sair</a></p>
    </div>
  `));
});

app.get('/logout', (req,res)=>{ 
  res.clearCookie('vol_session'); 
  res.redirect('/login'); 
});

app.post('/meu/atualizar', requireVolunteer, upload.single('cac_pdf'), async (req, res) => {
  try {
    const id = req.vol.volunteer_id;
    if (req.body.consent !== 'on') return res.status(400).send('Confirme o consentimento.');

    let oldPdfPath = null;
    if (req.file) {
      const { rows } = await pool.query('SELECT pdf_path FROM cadastros WHERE id = $1', [id]);
      if (rows.length > 0) {
        oldPdfPath = rows[0].pdf_path;
      }
    }

    const updates = [];
    const params = [];
    let idx = 1;

    if (req.body.email) { updates.push(`email=$${idx++}`); params.push(req.body.email.trim()); }

    if (req.file) {
      if (req.file.mimetype !== 'application/pdf') return res.status(400).send('Envie um PDF válido.');
      const pdfBuffer = req.file.buffer;
      const pdf_sha256 = crypto.createHash('sha256').update(pdfBuffer).digest('hex');
      
      const { cert_number, issued_at, expires_at, cac_result } = await extractFromPdf(pdfBuffer);

      const key = `cac/${Date.now()}_${cert_number || 'sem-numero'}.pdf`;
      
      const { error: uploadError } = await supabase.storage
          .from(process.env.SUPABASE_BUCKET)
          .upload(key, pdfBuffer, { contentType: 'application/pdf', upsert: true });

      if (uploadError) throw uploadError;

      updates.push(`cert_number=$${idx++}`); params.push(cert_number);
      updates.push(`issued_at=$${idx++}`); params.push((issued_at && issued_at.isValid()) ? issued_at.toISOString() : null);
      updates.push(`expires_at=$${idx++}`); params.push((expires_at && expires_at.isValid()) ? expires_at.toISOString() : null);
      updates.push(`pdf_path=$${idx++}`); params.push(key);
      updates.push(`pdf_sha256=$${idx++}`); params.push(pdf_sha256);
      updates.push(`cac_result=$${idx++}`); params.push(cac_result);

      let status = 'em_revisao';
      if (issued_at && expires_at && issued_at.isValid()) {
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
      updates.push(`status=$${idx++}`); params.push(status);
    }

    updates.push(`consent_signed_at=NOW()`);
    updates.push(`updated_at=NOW()`);

    params.push(id);
    const q = `UPDATE cadastros SET ${updates.join(', ')} WHERE id=$${idx} RETURNING id`;
    await pool.query(q, params);
    
    if (oldPdfPath) {
      try {
        await supabase.storage.from(process.env.SUPABASE_BUCKET).remove([oldPdfPath]);
      } catch (removeError) {
        console.error("Erro ao deletar PDF antigo, mas o cadastro foi atualizado:", removeError);
      }
    }

    res.redirect('/meu/painel');
  } catch (e) {
    console.error(e);
    res.status(500).send('Erro ao atualizar.');
  }
});

// ===== Reset de senha voluntário =====
app.get('/forgot', (_req,res)=> {
  res.send(page('Esqueci minha senha', `
    <div class="max-w-sm mx-auto bg-white border rounded-xl p-6">
      <h2 class="text-xl font-semibold mb-3">Recuperar senha</h2>
      <form method="post" action="/forgot" class="space-y-3">
        <div><label class="block text-sm">E-mail</label><input name="email" class="w-full border rounded px-3 py-2" required/></div>
        <button class="btn-brand px-4 py-2 rounded">Enviar link</button>
      </form>
    </div>
  `));
});

app.post('/forgot', async (req,res)=> {
  const email = (req.body.email||'').trim();
  const { rows } = await pool.query('SELECT id FROM cadastros WHERE email=$1 LIMIT 1', [email]);
  if (!rows.length) return res.send(page('OK', '<p>Se existir conta, enviaremos um e-mail.</p>'));

  const token = crypto.randomBytes(24).toString('hex');
  await pool.query('UPDATE cadastros SET reset_token=$1, reset_expires=NOW()+INTERVAL \'1 day\' WHERE id=$2', [token, rows[0].id]);
  const link = `${process.env.APP_BASE_URL || ''}/reset?token=${token}`;

  if (transporter) {
    await transporter.sendMail({ from: process.env.MAIL_FROM || 'no-reply@example.com', to: email,
      subject: 'Redefinição de senha', html: `Clique aqui para redefinir: <a href="${link}">${link}</a>` });
  }

  res.send(page('OK', `<p>Se existir conta, enviaremos um e-mail. Link: <span class="text-xs">${link}</span></p>`));
});

app.get('/reset', async (req,res)=> {
  const { rows } = await pool.query('SELECT id FROM cadastros WHERE reset_token=$1 AND reset_expires>NOW() LIMIT 1', [req.query.token]);
  if (!rows.length) return res.send(page('Reset', '<p>Link inválido ou expirado.</p>'));
  res.send(page('Definir nova senha', `
    <form method="post" action="/reset?token=${req.query.token}" class="max-w-sm mx-auto bg-white border rounded-xl p-6 space-y-3">
      <div><label class="block text-sm">Nova senha</label><input type="password" name="password" class="w-full border rounded px-3 py-2" required/></div>
      <button class="btn-brand px-4 py-2 rounded">Salvar</button>
    </form>
  `));
});

app.post('/reset', async (req,res)=> {
  const token = req.query.token;
  const { rows } = await pool.query('SELECT id FROM cadastros WHERE reset_token=$1 AND reset_expires>NOW() LIMIT 1', [token]);
  if (!rows.length) return res.send(page('Reset', '<p>Link inválido ou expirado.</p>'));
  const hash = await bcrypt.hash(req.body.password || '', 10);
  await pool.query('UPDATE cadastros SET password_hash=$1, reset_token=NULL, reset_expires=NULL WHERE id=$2', [hash, rows[0].id]);
  res.send(page('OK', '<p>Senha atualizada. <a href="/login" class="link-brand underline">Entrar</a></p>'));
});
// ===== Admin =====
app.get('/admin/login', (_req, res) => {
  res.send(adminPage('Login Admin', `
    <div class="max-w-sm mx-auto bg-white border rounded-xl p-6">
      <h2 class="text-xl font-semibold mb-4">Acesso do administrador</h2>
      <form method="post" action="/admin/login" class="space-y-3">
        <div><label class="block text-sm">E-mail</label><input name="email" class="w-full border rounded px-3 py-2" required/></div>
        <div><label class="block text-sm">Senha</label><input type="password" name="password" class="w-full border rounded px-3 py-2" required/></div>
        <button class="btn-brand px-4 py-2 rounded">Entrar</button>
      </form>
    </div>
  `));
});

app.post('/admin/login', async (req,res)=>{
  const { email, password } = req.body || {};
  // super admin via env
  if (email === process.env.SUPER_ADMIN_EMAIL && password === process.env.SUPER_ADMIN_PASS) {
    const t = signToken({ role: 'admin:super', email, admin_id: 0 }, 'SESSION_SECRET');
    res.cookie('admin_session', t, { httpOnly: true, sameSite:'lax', secure:true });
    return res.redirect('/admin/painel');
  }
  // admins do banco
  const { rows } = await pool.query('SELECT id,password_hash,role FROM admins WHERE email=$1 LIMIT 1', [email?.trim()]);
  if (!rows.length || !(await bcrypt.compare(password || '', rows[0].password_hash || '')))
    return res.send(adminPage('Login', '<p>Credenciais inválidas.</p>'));
  const token = signToken({ role: `admin:${rows[0].role}`, email: email.trim(), admin_id: rows[0].id });
  res.cookie('admin_session', token, { httpOnly: true, sameSite:'lax', secure:true });
  res.redirect('/admin/painel');
});

app.get('/admin/logout', (req,res)=>{ res.clearCookie('admin_session'); res.redirect('/admin/login'); });

app.get('/admin/painel', requireAdmin, async (_req,res)=>{
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
      <div><label class="block text-sm">Senha</label><input type="password" name="password" class="w-full border rounded px-3 py-2" required/></div>
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

// Rota para visualizar PDF do Supabase
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

// ===== Cron housekeeping =====
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

// Start server
app.listen(process.env.PORT || 3000, () => console.log(`On-line na porta ${process.env.PORT || 3000}`));