// ════════════════════════════════════════════════════
// PIÈCES UNIK — SERVEUR ADMIN (fichier unique)
// Garde la clé secrète Supabase côté serveur, jamais exposée
// au navigateur. L'admin appelle ce serveur, pas Supabase
// directement.
// ════════════════════════════════════════════════════

import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import helmet from 'helmet';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'node:crypto';
import { createClient } from '@supabase/supabase-js';

const app = express();
const PORT = process.env.PORT || 3000;
const sb = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

// ════════════════════════════════════════════════════
// SÉCURITÉ DE BASE
// ════════════════════════════════════════════════════
app.use(helmet()); // cache "X-Powered-By: Express", ajoute des en-têtes de sécurité standards
app.use(express.json({
  limit: '15mb', // 15mb pour les images en base64 uploadées
  // Garde le corps brut : indispensable pour vérifier la signature des webhooks Paystack
  verify: (req, res, buf) => { req.rawBody = buf; },
}));
app.use(cookieParser());
// ALLOWED_ORIGIN accepte une ou plusieurs adresses séparées par des virgules, ex :
// https://www.streetleger.shop,https://www.streetleger.cloud
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGIN || '')
  .split(',').map(s => s.trim().replace(/\/$/, '')).filter(Boolean);
app.use(cors({
  origin: ALLOWED_ORIGINS.length ? ALLOWED_ORIGINS : true,
  credentials: true, // nécessaire pour que le cookie de session soit envoyé/reçu
}));

// ════════════════════════════════════════════════════
// AUTHENTIFICATION
// ════════════════════════════════════════════════════
const COOKIE_NAME = 'sl_session';
const COOKIE_OPTS = {
  httpOnly: true, // jamais accessible depuis le JS du navigateur (protège contre le vol par script)
  secure: process.env.NODE_ENV === 'production', // HTTPS obligatoire en production (Render), désactivé en local pour pouvoir tester
  sameSite: 'strict', // protège contre les attaques CSRF
  maxAge: 1000 * 60 * 60 * 12, // 12 heures
};

// Limite anti brute-force simple : trop de tentatives échouées récentes bloque temporairement
const failedAttempts = new Map(); // ip -> { count, lastTry }
const MAX_ATTEMPTS = 5;
const LOCKOUT_MS = 15 * 60 * 1000; // 15 minutes

function isLockedOut(ip) {
  const entry = failedAttempts.get(ip);
  if (!entry) return false;
  if (entry.count < MAX_ATTEMPTS) return false;
  const elapsed = Date.now() - entry.lastTry;
  if (elapsed > LOCKOUT_MS) {
    failedAttempts.delete(ip);
    return false;
  }
  return true;
}

function recordFailedAttempt(ip) {
  const entry = failedAttempts.get(ip) || { count: 0, lastTry: 0 };
  entry.count += 1;
  entry.lastTry = Date.now();
  failedAttempts.set(ip, entry);
}

function clearFailedAttempts(ip) {
  failedAttempts.delete(ip);
}

// Récupère le hash du mot de passe actuel — priorité à Supabase (modifiable depuis l'admin),
// repli sur la variable d'environnement si jamais changé depuis l'interface.
async function getCurrentPasswordHash() {
  try {
    const { data, error } = await sb
      .from('site_settings')
      .select('admin_pass_hash')
      .eq('id', 'main')
      .single();
    if (!error && data?.admin_pass_hash) return data.admin_pass_hash;
  } catch (e) {
    console.warn('Impossible de lire le mot de passe depuis Supabase, utilisation du repli env:', e.message);
  }
  // Repli : hash de la variable d'environnement ADMIN_PASSWORD, calculé à la volée
  return bcrypt.hashSync(process.env.ADMIN_PASSWORD || 'changeme', 10);
}

function requireAuth(req, res, next) {
  const token = req.cookies?.[COOKIE_NAME];
  if (!token) {
    return res.status(401).json({ error: 'Non connecté' });
  }
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.user = payload; // { username, iat, exp }
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Session invalide ou expirée' });
  }
}

// ───────── Routes d'authentification ─────────
app.post('/api/auth/login', async (req, res) => {
  const ip = req.ip;
  if (isLockedOut(ip)) {
    return res.status(429).json({ error: 'Trop de tentatives. Réessaie dans 15 minutes.' });
  }

  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: "Nom d'utilisateur et mot de passe requis" });
  }
  if (username !== (process.env.ADMIN_USERNAME || 'admin')) {
    recordFailedAttempt(ip);
    return res.status(401).json({ error: 'Identifiants incorrects' });
  }

  const currentHash = await getCurrentPasswordHash();
  const valid = bcrypt.compareSync(password, currentHash);
  if (!valid) {
    recordFailedAttempt(ip);
    return res.status(401).json({ error: 'Identifiants incorrects' });
  }

  clearFailedAttempts(ip);
  const token = jwt.sign({ username }, process.env.JWT_SECRET, { expiresIn: '12h' });
  res.cookie(COOKIE_NAME, token, COOKIE_OPTS);
  res.json({ ok: true, username });
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie(COOKIE_NAME, { httpOnly: true, secure: COOKIE_OPTS.secure, sameSite: 'strict' });
  res.json({ ok: true });
});

app.get('/api/auth/me', (req, res) => {
  const token = req.cookies?.[COOKIE_NAME];
  if (!token) return res.status(401).json({ authenticated: false });
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    res.json({ authenticated: true, username: payload.username });
  } catch {
    res.status(401).json({ authenticated: false });
  }
});

// Changer le mot de passe — nécessite d'être déjà connecté
app.post('/api/auth/change-password', async (req, res) => {
  const token = req.cookies?.[COOKIE_NAME];
  if (!token) return res.status(401).json({ error: 'Non connecté' });
  try {
    jwt.verify(token, process.env.JWT_SECRET);
  } catch {
    return res.status(401).json({ error: 'Session invalide' });
  }

  const { currentPassword, newPassword } = req.body || {};
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'Mot de passe actuel et nouveau requis' });
  }
  if (newPassword.length < 6) {
    return res.status(400).json({ error: 'Le nouveau mot de passe doit faire au moins 6 caractères' });
  }

  const currentHash = await getCurrentPasswordHash();
  const valid = bcrypt.compareSync(currentPassword, currentHash);
  if (!valid) {
    return res.status(401).json({ error: 'Mot de passe actuel incorrect' });
  }

  const newHash = bcrypt.hashSync(newPassword, 10);
  const { error } = await sb
    .from('site_settings')
    .update({ admin_pass_hash: newHash })
    .eq('id', 'main');

  if (error) {
    console.error('Erreur sauvegarde nouveau mot de passe:', error);
    return res.status(500).json({ error: 'Erreur lors de la sauvegarde' });
  }

  res.json({ ok: true });
});

// ════════════════════════════════════════════════════
// PAIEMENT PAYSTACK
// Le site appelle CETTE route (jamais Paystack directement) pour que
// la clé secrète Paystack (sk_live_...) reste uniquement côté serveur.
// ════════════════════════════════════════════════════
const PAYSTACK_API = 'https://api.paystack.co';
// Nettoie la clé collée dans Render : espaces, retours à la ligne et guillemets en trop
// font échouer toute requête ("Invalid character in header").
function paystackKey() {
  return (process.env.PAYSTACK_SECRET_KEY || '').trim().replace(/^["']+|["']+$/g, '').trim();
}
const PAYSTACK_CURRENCY = process.env.PAYSTACK_CURRENCY || 'XOF';
// Paystack attend le montant dans la sous-unité de la devise.
// Par défaut ×100. Si ton test à petit montant affiche un total 100× trop grand,
// mets PAYSTACK_AMOUNT_MULTIPLIER=1 dans les variables d'environnement Render.
const PAYSTACK_MULT = Number(process.env.PAYSTACK_AMOUNT_MULTIPLIER || 100);
const PAYSTACK_CHANNELS = (process.env.PAYSTACK_CHANNELS || 'mobile_money,card')
  .split(',').map(s => s.trim()).filter(Boolean);

async function paystackRequest(path, options = {}) {
  const response = await fetch(PAYSTACK_API + path, {
    ...options,
    headers: {
      Authorization: `Bearer ${paystackKey()}`,
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
  });
  const json = await response.json().catch(() => ({}));
  return { ok: response.ok && json.status === true, json };
}

function isValidEmail(v) {
  return typeof v === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(v.trim());
}

app.post('/api/payments/create', async (req, res) => {
  const { orderId, clientName, clientPhone, clientEmail } = req.body || {};

  // Seul orderId est indispensable : Paystack n'a pas besoin du téléphone pour encaisser.
  if (!orderId) {
    return res.status(400).json({ error: 'orderId est requis' });
  }
  if (!paystackKey()) {
    return res.status(503).json({ error: "Paystack n'est pas encore configuré sur le serveur (PAYSTACK_SECRET_KEY manquant)" });
  }

  try {
    // SÉCURITÉ : le montant n'est JAMAIS pris depuis le navigateur (il pourrait être falsifié).
    // On relit le vrai total de la commande dans Supabase.
    const { data: order, error: orderErr } = await sb
      .from('orders').select('id,total,payment_status').eq('id', orderId).single();
    if (orderErr || !order) {
      // PGRST116 = aucune ligne trouvée ; tout autre code = vrai problème de configuration/base
      console.error(`Lecture commande ${orderId} impossible:`, orderErr?.code, orderErr?.message, orderErr?.details || '');
      if (orderErr && orderErr.code !== 'PGRST116') {
        return res.status(500).json({ error: `Erreur base de données (${orderErr.code || 'inconnue'}) : ${orderErr.message}` });
      }
      return res.status(404).json({ error: `Commande ${orderId} absente de la base du serveur (vérifie SUPABASE_URL sur Render)` });
    }
    if (order.payment_status === 'paid') {
      return res.status(409).json({ error: 'Cette commande est déjà payée' });
    }
    const total = Number(order.total);
    if (!Number.isFinite(total) || total <= 0) {
      return res.status(400).json({ error: 'Montant de commande invalide' });
    }

    // Paystack exige un email. Si le client n'en a pas donné, on en génère un technique.
    const email = isValidEmail(clientEmail)
      ? clientEmail.trim()
      : `${String(orderId).toLowerCase().replace(/[^a-z0-9]/g, '')}@${process.env.PAYSTACK_FALLBACK_EMAIL_DOMAIN || 'streetleger.com'}`;

    const { ok, json } = await paystackRequest('/transaction/initialize', {
      method: 'POST',
      body: JSON.stringify({
        email,
        amount: Math.round(total * PAYSTACK_MULT),
        currency: PAYSTACK_CURRENCY,
        reference: `${orderId}-${Date.now().toString(36)}`, // unique à chaque tentative de paiement
        callback_url: process.env.PAYSTACK_CALLBACK_URL,
        channels: PAYSTACK_CHANNELS,
        metadata: {
          orderId,
          clientName: clientName || 'Client',
          clientPhone: clientPhone || '',
        },
      }),
    });

    if (!ok) {
      console.error('Paystack a refusé la création du paiement:', json);
      let msg = json.message || 'Erreur Paystack';
      // Refus pour cause de liste blanche d'IP : on indique l'IP exacte que Paystack voit
      if (/ip address/i.test(msg)) {
        try {
          const ipRes = await fetch('https://api.ipify.org?format=json');
          const ipData = await ipRes.json();
          msg += ` | IP vue par Paystack : ${ipData.ip} | mode de la clé : ${paystackKey().startsWith('sk_live_') ? 'LIVE' : 'TEST'}`;
        } catch {}
      }
      return res.status(502).json({ error: msg });
    }

    // authorization_url = page Paystack vers laquelle on redirige le client pour payer
    res.json({
      ok: true,
      paymentUrl: json.data.authorization_url,
      reference: json.data.reference,
    });
  } catch (err) {
    console.error('Erreur appel Paystack:', err, err?.cause || '');
    const detail = [err?.message, err?.cause?.code || err?.cause?.message].filter(Boolean).join(' / ');
    res.status(500).json({ error: `Impossible de contacter Paystack (${detail || 'erreur inconnue'})` });
  }
});

// ────────────────────────────────────────────────────
// Règle un paiement : interroge Paystack (source de vérité), contrôle le montant,
// puis met à jour la commande. Idempotent : peut être appelé plusieurs fois
// (webhook + page de retour) sans doublon comptable.
// ────────────────────────────────────────────────────
async function settlePayment(reference) {
  const { ok, json } = await paystackRequest(`/transaction/verify/${encodeURIComponent(reference)}`);
  if (!ok) throw new Error(json.message || 'Vérification Paystack impossible');

  const tx = json.data;
  const orderId = tx?.metadata?.orderId;
  if (!orderId) return { status: 'unknown', orderId: null };

  const { data: order } = await sb
    .from('orders').select('id,client,total,payment_status').eq('id', orderId).single();
  if (!order) return { status: 'unknown', orderId };

  // Déjà payée : rien à refaire
  if (order.payment_status === 'paid') return { status: 'paid', orderId };

  let newStatus;
  if (tx.status === 'success') {
    // Le montant et la devise confirmés par Paystack doivent correspondre à la commande
    const expected = Math.round(Number(order.total) * PAYSTACK_MULT);
    if (Math.abs(Number(tx.amount) - expected) > PAYSTACK_MULT || tx.currency !== PAYSTACK_CURRENCY) {
      console.error(`⚠️ Montant/devise incohérent pour ${orderId} : attendu=${expected} ${PAYSTACK_CURRENCY}, Paystack=${tx.amount} ${tx.currency}. Ignoré par sécurité.`);
      return { status: 'mismatch', orderId };
    }
    newStatus = 'paid';
  } else if (tx.status === 'failed' || tx.status === 'abandoned' || tx.status === 'reversed') {
    newStatus = 'failed';
  } else {
    newStatus = 'pending'; // ongoing, pending, processing, queued…
  }

  const { error } = await sb
    .from('orders')
    .update({ payment_status: newStatus, payment_token: reference })
    .eq('id', orderId);
  if (error) throw new Error('Erreur base de données: ' + error.message);

  console.log(`✓ Commande ${orderId} marquée ${newStatus} via Paystack (${reference})`);

  // Paiement confirmé → enregistre la vente en comptabilité (une seule fois)
  if (newStatus === 'paid') {
    try {
      const { data: existingTx } = await sb.from('transactions').select('id').eq('id', 'TX-' + orderId).maybeSingle();
      if (!existingTx) {
        await sb.from('transactions').insert({
          id: 'TX-' + orderId,
          date: new Date().toISOString().split('T')[0],
          description: `Vente ${orderId} — ${order.client}`,
          category: 'Vente',
          fourn_id: null,
          amount_in: order.total,
          amount_out: 0,
        });
      }
    } catch (txErr) {
      console.warn('Transaction compta non enregistrée:', txErr.message);
    }
  }
  return { status: newStatus, orderId };
}

// ════════════════════════════════════════════════════
// WEBHOOK PAYSTACK — Paystack appelle cette route depuis SES serveurs
// dès qu'un paiement est confirmé. Chaque requête est signée (HMAC SHA-512
// du corps brut avec ta clé secrète) : on rejette tout ce qui n'est pas signé.
// URL à renseigner dans Paystack > Settings > API Keys & Webhooks :
//   https://TON-SERVEUR.onrender.com/api/webhooks/paystack
// ════════════════════════════════════════════════════
app.post('/api/webhooks/paystack', async (req, res) => {
  try {
    const signature = req.get('x-paystack-signature') || '';
    if (!paystackKey() || !req.rawBody) {
      return res.status(503).end();
    }
    const expected = crypto
      .createHmac('sha512', paystackKey())
      .update(req.rawBody)
      .digest('hex');
    const a = Buffer.from(signature, 'utf8');
    const b = Buffer.from(expected, 'utf8');
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      console.warn('Webhook Paystack rejeté : signature invalide');
      return res.status(401).end();
    }

    const { event, data } = req.body || {};
    console.log('Webhook Paystack reçu:', event, data?.reference);

    if (event === 'charge.success' && data?.reference) {
      await settlePayment(data.reference);
    }
    // Paystack attend un 200 rapide pour considérer la notification comme reçue.
    res.status(200).json({ ok: true });
  } catch (err) {
    console.error('Erreur traitement webhook Paystack:', err);
    // 500 → Paystack réessaiera automatiquement plus tard
    res.status(500).json({ ok: false });
  }
});

// Appelée par le site quand le client revient de Paystack : confirme le statut
// sans attendre le webhook. Ne peut rien falsifier : la réponse vient de Paystack.
app.get('/api/payments/verify/:reference', async (req, res) => {
  if (!paystackKey()) {
    return res.status(503).json({ error: 'Paystack non configuré' });
  }
  try {
    const result = await settlePayment(req.params.reference);
    res.json({ ok: true, ...result });
  } catch (err) {
    console.error('Erreur vérification Paystack:', err);
    res.status(502).json({ error: 'Vérification impossible pour le moment' });
  }
});

// ════════════════════════════════════════════════════
// DIAGNOSTIC — révèle la vraie IP sortante du serveur
// (utile si tu veux restreindre l'accès API dans le dashboard Paystack)
// ════════════════════════════════════════════════════
app.get('/api/my-outbound-ip', async (req, res) => {
  try {
    const response = await fetch('https://api.ipify.org?format=json');
    const data = await response.json();
    res.json({ outboundIp: data.ip });
  } catch (err) {
    res.status(500).json({ error: 'Impossible de déterminer l\'IP sortante' });
  }
});

// ════════════════════════════════════════════════════
// ASSISTANT VOCAL : compréhension du langage par ChatGPT (OpenAI)
// La clé OPENAI_API_KEY reste ICI (variable d'environnement Render), jamais dans le site.
// Sans clé, le site marche quand même avec ses règles locales.
// ════════════════════════════════════════════════════
const NLU_HITS = new Map();            // ip -> [timestamps]
const NLU_DAY = { d: '', n: 0 };
const NLU_PER_IP = Number(process.env.NLU_MAX_PER_10MIN || 60);
const NLU_PER_DAY = Number(process.env.NLU_DAILY_MAX || 4000);
function nluAllowed(ip) {
  const now = Date.now(), day = new Date().toISOString().slice(0, 10);
  if (NLU_DAY.d !== day) { NLU_DAY.d = day; NLU_DAY.n = 0; }
  if (NLU_DAY.n >= NLU_PER_DAY) return false;
  const arr = (NLU_HITS.get(ip) || []).filter(t => now - t < 10 * 60 * 1000);
  if (arr.length >= NLU_PER_IP) { NLU_HITS.set(ip, arr); return false; }
  arr.push(now); NLU_HITS.set(ip, arr); NLU_DAY.n++;
  if (NLU_HITS.size > 5000) for (const [k, v] of NLU_HITS) if (!v.length || now - v[v.length - 1] > 600000) NLU_HITS.delete(k);
  return true;
}
const NLU_SYSTEM = `Tu es l'assistant vocal d'une boutique de cosmétiques (savons, huiles, parfums) en Côte d'Ivoire.
Les clientes sont souvent des mamans qui ne savent pas lire ni écrire : elles parlent un français simple, parfois ivoirien. La transcription vocale contient des erreurs : rapproche ce qui est dit des noms du catalogue par le SON (ex. "molato" ≈ un produit qui sonne pareil).
Tu ne vends QUE ce qui est dans le catalogue fourni (id, n=nom, g=gamme, p=prix FCFA, s=contenances, o=contenances en rupture). Tu n'inventes jamais un produit, un prix ou une disponibilité.
Tu reçois l'état de la commande (étape "phase", dernière question posée "question", panier, nom, téléphone, lieu) et la phrase du client ("utterance", "alts" = autres transcriptions possibles).
Réponds UNIQUEMENT par un objet JSON avec ces clés :
- "add": [{"id":<id catalogue>,"size":"<contenance ou null>","qty":<entier>=1}] produits que le client veut AJOUTER maintenant (une gamme + "le lait et l'huile" = les produits de CETTE gamme correspondants).
- "remove": [<id>] produits à retirer. "set_qty": [{"id":<id>,"qty":<entier>}] pour changer une quantité.
- "name": nom du client s'il le donne ou le corrige (sans "je m'appelle"). "phone": numéro en chiffres (10 chiffres) s'il le donne. "lieu": lieu de livraison s'il le donne.
- "redo": "name" | "phone" | "lieu" | "order" si le client dit qu'une information est fausse/qu'on s'est trompé ou veut la redonner SANS donner la nouvelle valeur dans la même phrase. Sinon null.
- "finish": true si le client dit que sa commande est complète ou bonne ou qu'on peut continuer ("c'est tout", "ma commande est bonne", "voilà", "tout est bon", "valide").
- "yes" / "no": true si c'est une réponse oui / non à la dernière question posée.
- "say": une ou deux phrases courtes, simples, en tutoyant, UNIQUEMENT pour répondre à une question du client (disponibilité, prix, contenances, produits d'une gamme, "je paie comment ?" = paiement à la livraison) ou pour demander une précision quand tu n'as pas compris ou qu'un produit est ambigu. Sinon null. N'écris jamais "j'ai ajouté" : le système le dit lui-même.
- "offer_id": l'id du produit dont tu parles dans "say" si tu proposes de le prendre, sinon null.
Règles : si le client demande seulement si un produit existe ou son prix, n'ajoute rien : réponds dans "say" avec le prix et les contenances et demande s'il en veut. Si "offer" est fourni et que le client dit oui / donne une quantité, ajoute ce produit. Si le client donne plusieurs produits dans une phrase, ajoute-les tous. Quantité absente = 1. Ne mets une valeur dans name/phone/lieu que si le client la dit réellement.`;
function nluClean(j) {
  const out = { add: [], remove: [], set_qty: [], name: null, phone: null, lieu: null, redo: null, finish: false, yes: false, no: false, say: null, offer_id: null };
  if (!j || typeof j !== 'object') return out;
  if (Array.isArray(j.add)) out.add = j.add.slice(0, 12).map(a => ({ id: a && a.id, size: a && a.size ? String(a.size).slice(0, 40) : null, qty: Math.max(1, Math.min(100000, parseInt(a && a.qty, 10) || 1)) })).filter(a => a.id !== undefined && a.id !== null);
  if (Array.isArray(j.remove)) out.remove = j.remove.slice(0, 12);
  if (Array.isArray(j.set_qty)) out.set_qty = j.set_qty.slice(0, 12).map(a => ({ id: a && a.id, qty: Math.max(1, Math.min(100000, parseInt(a && a.qty, 10) || 1)) }));
  if (typeof j.name === 'string' && j.name.trim()) out.name = j.name.trim().slice(0, 60);
  if (j.phone != null && String(j.phone).replace(/\D/g, '')) out.phone = String(j.phone).replace(/\D/g, '').slice(0, 15);
  if (typeof j.lieu === 'string' && j.lieu.trim()) out.lieu = j.lieu.trim().slice(0, 120);
  if (['name', 'phone', 'lieu', 'order'].includes(j.redo)) out.redo = j.redo;
  out.finish = j.finish === true; out.yes = j.yes === true; out.no = j.no === true;
  if (typeof j.say === 'string' && j.say.trim()) out.say = j.say.trim().slice(0, 400);
  if (j.offer_id !== undefined && j.offer_id !== null) out.offer_id = j.offer_id;
  return out;
}
// Fournisseur d'IA au choix (tout service compatible OpenAI) :
//   LLM_API_KEY  = ta clé (ou OPENAI_API_KEY, ancien nom)
//   LLM_BASE_URL = adresse du service (défaut OpenAI). Gemini : https://generativelanguage.googleapis.com/v1beta/openai
//   LLM_MODEL    = nom du modèle (défaut gpt-4o-mini ; pour Gemini mets un modèle Gemini "flash" de ta console Google)
const LLM_KEY = () => process.env.LLM_API_KEY || process.env.OPENAI_API_KEY || '';
const LLM_URL = () => (process.env.LLM_BASE_URL || 'https://api.openai.com/v1').replace(/\/$/, '') + '/chat/completions';
const LLM_MODEL = () => process.env.LLM_MODEL || process.env.OPENAI_MODEL || 'gpt-4o-mini';
app.get('/api/voice-nlu/ping', (req, res) => res.json({ ok: true, llm: !!LLM_KEY() }));
app.post('/api/voice-nlu', async (req, res) => {
  if (!LLM_KEY()) return res.status(501).json({ error: 'nlu_off' });
  const ip = req.ip || req.headers['x-forwarded-for'] || 'x';
  if (!nluAllowed(ip)) return res.status(429).json({ error: 'trop_de_demandes' });
  const b = req.body || {};
  const utterance = String(b.utterance || '').slice(0, 500);
  if (!utterance.trim()) return res.status(400).json({ error: 'vide' });
  const state = {
    shop: String(b.shop || '').slice(0, 60), phase: String(b.phase || '').slice(0, 20), question: String(b.question || '').slice(0, 300),
    utterance, alts: Array.isArray(b.alts) ? b.alts.slice(0, 2).map(x => String(x).slice(0, 300)) : [],
    basket: Array.isArray(b.basket) ? b.basket.slice(0, 30) : [], name: String(b.name || '').slice(0, 60), phone: String(b.phone || '').slice(0, 20),
    phone_confirmed: !!b.phone_confirmed, lieu: String(b.lieu || '').slice(0, 120), gamme_en_cours: String(b.gamme || '').slice(0, 60),
    offer: b.offer && typeof b.offer === 'object' ? { id: b.offer.id, name: String(b.offer.name || '').slice(0, 80) } : null,
    historique: Array.isArray(b.history) ? b.history.slice(-6).map(x => String(x).slice(0, 200)) : [],
    catalog: Array.isArray(b.catalog) ? b.catalog.slice(0, 300) : [],
  };
  const ctl = new AbortController();
  const to = setTimeout(() => ctl.abort(), 9000);
  try {
    const r = await fetch(LLM_URL(), {
      method: 'POST', signal: ctl.signal,
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + LLM_KEY() },
      body: JSON.stringify({
        model: LLM_MODEL(), temperature: 0.2, max_tokens: 400,
        response_format: { type: 'json_object' },
        messages: [{ role: 'system', content: NLU_SYSTEM }, { role: 'user', content: JSON.stringify(state) }],
      }),
    });
    if (!r.ok) { console.error('LLM', r.status, (await r.text().catch(() => '')).slice(0, 200)); return res.status(502).json({ error: 'nlu_indisponible' }); }
    const data = await r.json();
    let parsed = null;
    try { parsed = JSON.parse(data.choices[0].message.content); } catch {}
    res.json(nluClean(parsed));
  } catch (e) {
    console.error('NLU', e && e.message);
    res.status(502).json({ error: 'nlu_indisponible' });
  } finally { clearTimeout(to); }
});

// ════════════════════════════════════════════════════
// VÉRIFICATION DE SANTÉ (pour Render et pour toi)
// ════════════════════════════════════════════════════
app.get('/api/health', async (req, res) => {
  // Diagnostic sans secret : montre quel projet Supabase le serveur utilise
  // et s'il arrive à lire la table des commandes.
  let supabaseHost = null;
  try { supabaseHost = new URL(process.env.SUPABASE_URL).host; } catch {}
  // (pas de requête HEAD : elle ne renvoie aucun message d'erreur lisible)
  const { data: sample, error, status } = await sb.from('orders').select('id,total,payment_status').limit(1);
  const count = sample ? sample.length : null;
  res.json({
    ok: true,
    time: new Date().toISOString(),
    version: 'paystack-v8-piecesunik',
    supabaseHost,
    ordersReadable: !error,
    ordersSampleRows: error ? null : count,
    httpStatus: status,
    ordersError: error ? `${error.code || ''} ${error.message || ''} ${error.details || ''} ${error.hint || ''}`.trim() || JSON.stringify(error) : null,
    paystackKeyConfigured: !!paystackKey(),
    paystackKeyMode: paystackKey().startsWith('sk_live_') ? 'live' : paystackKey().startsWith('sk_test_') ? 'test' : 'FORMAT INVALIDE (doit commencer par sk_test_ ou sk_live_)',
    paystackKeyHadStrayChars: (process.env.PAYSTACK_SECRET_KEY || '') !== paystackKey(),
    paystackKeyLength: paystackKey().length,
    callbackUrl: process.env.PAYSTACK_CALLBACK_URL || null,
  });
});

// ════════════════════════════════════════════════════
// DONNÉES — proxy sécurisé vers Supabase (clé secrète jamais exposée)
// ════════════════════════════════════════════════════

// Tables que l'admin a le droit de lire/modifier via ce serveur.
// Toute table absente de cette liste est inaccessible, même avec une session valide —
// ça évite qu'une faille d'un autre endroit du code permette de toucher n'importe quoi.
const ALLOWED_TABLES = new Set([
  'categories', 'fournisseurs', 'products', 'orders', 'promos',
  'transactions', 'slides', 'site_texts', 'site_settings', 'nav_links',
  'supplier_payouts', 'gammes', 'livreurs', 'stock_moves', 'site_events',
]);

function checkTable(req, res, next) {
  const { table } = req.params;
  if (!ALLOWED_TABLES.has(table)) {
    return res.status(403).json({ error: `Table non autorisée : ${table}` });
  }
  next();
}

// GET /api/data/:table — liste tout (avec filtres optionnels en query string)
app.get('/api/data/:table', requireAuth, checkTable, async (req, res) => {
  const { table } = req.params;
  let query = sb.from(table).select('*');

  // Filtres simples optionnels : ?eq_id=123 filtre où id=123
  Object.entries(req.query).forEach(([key, value]) => {
    if (key.startsWith('eq_')) {
      query = query.eq(key.replace('eq_', ''), value);
    }
  });

  const { data, error } = await query;
  if (error) return res.status(500).json({ error: error.message });
  res.json({ data });
});

// POST /api/data/:table — insère une nouvelle ligne
app.post('/api/data/:table', requireAuth, checkTable, async (req, res) => {
  const { table } = req.params;
  const { data, error } = await sb.from(table).insert(req.body).select();
  if (error) return res.status(500).json({ error: error.message });
  res.json({ data: data?.[0] || null });
});

// PUT /api/data/:table/:id — met à jour une ligne existante par son id
app.put('/api/data/:table/:id', requireAuth, checkTable, async (req, res) => {
  const { table, id } = req.params;
  const { data, error } = await sb.from(table).update(req.body).eq('id', id).select();
  if (error) return res.status(500).json({ error: error.message });
  res.json({ data: data?.[0] || null });
});

// DELETE /api/data/:table/:id — supprime une ligne par son id
app.delete('/api/data/:table/:id', requireAuth, checkTable, async (req, res) => {
  const { table, id } = req.params;
  const { error } = await sb.from(table).delete().eq('id', id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

// ════════════════════════════════════════════════════
// DÉMARRAGE
// ════════════════════════════════════════════════════
const server = app.listen(PORT, () => {
  console.log(`✓ Serveur Pièces Unik démarré sur le port ${PORT}`);
});

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`Port ${PORT} déjà utilisé — une autre instance tourne encore. Arrêt propre.`);
    process.exit(1);
  } else {
    console.error('Erreur serveur:', err);
    process.exit(1);
  }
});

// Arrêt propre quand Render envoie le signal de fin (avant un redéploiement)
// — libère le port immédiatement au lieu de rester accroché.
process.on('SIGTERM', () => {
  console.log('SIGTERM reçu, fermeture propre du serveur...');
  server.close(() => process.exit(0));
});
process.on('SIGINT', () => {
  console.log('SIGINT reçu, fermeture propre du serveur...');
  server.close(() => process.exit(0));
});
