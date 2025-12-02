require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const app = express();
app.use(cors({ origin: 'http://localhost:4242', credentials: false }));
app.use(express.json());

// ENV: JWT_SECRET, OWNER_EMAIL, BASE_FEE_PCT, BASE_FEE_FIXED
const JWT_SECRET = process.env.JWT_SECRET || 'change_me';
const OWNER_EMAIL = process.env.OWNER_EMAIL || 'owner@example.com';
const BASE_FEE_PCT = Number(process.env.BASE_FEE_PCT || 2.9);
const BASE_FEE_FIXED = Number(process.env.BASE_FEE_FIXED || 30);

// Demo stores (replace with a DB)
const users = new Map(); // email -> { email, passwordHash, role }
const tokens = new Map(); // token -> { last4, brand, expMonth, expYear, createdAt }
const authorizations = new Map(); // authId -> { amount, token, email, fee, captured, refunded }
const transactions = new Map(); // txnId -> { authId, amount, fee, settled }
const refunds = new Map(); // refundId -> { authId, amount }

// Utilities
const uuid = () => crypto.randomBytes(16).toString('hex');
const maskPAN = (pan) => pan.replace(/\D/g, '').slice(-4);
const detectBrand = (pan) => {
  const n = pan.replace(/\D/g, '');
  if (/^4/.test(n)) return 'visa';
  if (/^5[1-5]/.test(n)) return 'mastercard';
  if (/^3[47]/.test(n)) return 'amex';
  if (/^6(?:011|5)/.test(n)) return 'discover';
  return 'unknown';
};

function signToken(user) {
  return jwt.sign({ sub: user.email, role: user.role }, JWT_SECRET, { expiresIn: '2h' });
}

function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

function computePlatformFee(role, amountCents) {
  if (role === 'owner') return 0;
  const percentFee = Math.round(amountCents * (BASE_FEE_PCT / 100));
  return percentFee + BASE_FEE_FIXED;
}

// Seed owner
(function ensureOwner() {
  if (!users.has(OWNER_EMAIL)) {
    const hash = bcrypt.hashSync('change_this_owner_password', 10);
    users.set(OWNER_EMAIL, { email: OWNER_EMAIL, passwordHash: hash, role: 'owner' });
  }
})();

// Auth routes
app.post('/auth/signup', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  if (users.has(email)) return res.status(409).json({ error: 'Email already exists' });
  const role = email === OWNER_EMAIL ? 'owner' : 'merchant';
  const hash = await bcrypt.hash(password, 10);
  users.set(email, { email, passwordHash: hash, role });
  res.json({ ok: true });
});

app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  const u = users.get(email);
  if (!u) return res.status(404).json({ error: 'User not found' });
  const ok = await bcrypt.compare(password, u.passwordHash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
  const token = signToken(u);
  res.json({ token, user: { email: u.email, role: u.role } });
});

// Hosted fields: serve an isolated iframe for card entry
app.get('/hosted/fields', (req, res) => {
  // Minimal HTML page for the iframe. It tokenizes card data and posts a vaulted token to parent.
  res.setHeader('Content-Type', 'text/html');
  res.send(`
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Hosted Fields</title>
  <style>
    body { font-family: system-ui, sans-serif; margin: 0; padding: 12px; }
    .row { margin-bottom: 8px; }
    input { padding: 8px; border: 1px solid #d1d5db; border-radius: 6px; width: 100%; }
    .error { color: #b91c1c; font-size: 12px; }
    button { padding: 8px 12px; border: none; background: #111827; color: #fff; border-radius: 6px; cursor: pointer; }
  </style>
</head>
<body>
  <div class="row"><input id="pan" inputmode="numeric" autocomplete="off" placeholder="Card number" /></div>
  <div class="row" style="display:flex; gap:8px;">
    <input id="exp" inputmode="numeric" placeholder="MM/YY" />
    <input id="cvv" inputmode="numeric" placeholder="CVV" />
  </div>
  <div id="err" class="error"></div>
  <button id="tokenize">Tokenize</button>

  <script>
    const API_BASE = '${req.protocol}://${req.headers.host}';
    const errEl = document.getElementById('err');
    const postParent = (type, payload) => parent.postMessage({ type, payload }, 'http://localhost:4242');

    function luhnOk(number) {
      const n = number.replace(/\\D/g, '');
      let sum = 0, alt = false;
      for (let i = n.length - 1; i >= 0; i--) {
        let d = parseInt(n[i], 10);
        if (alt) { d *= 2; if (d > 9) d -= 9; }
        sum += d; alt = !alt;
      }
      return sum % 10 === 0;
    }

    async function tokenize() {
      errEl.textContent = '';
      const pan = document.getElementById('pan').value || '';
      const exp = document.getElementById('exp').value || '';
      const cvv = document.getElementById('cvv').value || '';

      const n = pan.replace(/\\D/g, '');
      if (n.length < 13 || n.length > 19 || !luhnOk(n)) {
        errEl.textContent = 'Invalid card number';
        postParent('error', { message: 'Invalid card number' });
        return;
      }
      const [mm, yy] = exp.split('/');
      const expMonth = parseInt(mm, 10), expYear = parseInt('20' + (yy || ''), 10);
      if (!expMonth || expMonth < 1 || expMonth > 12 || !expYear) {
        errEl.textContent = 'Invalid expiration';
        postParent('error', { message: 'Invalid expiration' });
        return;
      }
      if (!cvv || cvv.length < 3 || cvv.length > 4) {
        errEl.textContent = 'Invalid CVV';
        postParent('error', { message: 'Invalid CVV' });
        return;
      }

      try {
        const res = await fetch(API_BASE + '/vault/tokenize', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ pan: n, expMonth, expYear })
        });
        const data = await res.json();
        if (!res.ok) {
          errEl.textContent = data.error || 'Tokenization failed';
          postParent('error', { message: data.error || 'Tokenization failed' });
          return;
        }
        postParent('vaultedToken', { token: data.token });
      } catch (e) {
        errEl.textContent = 'Network error';
        postParent('error', { message: 'Network error' });
      }
    }

    document.getElementById('tokenize').addEventListener('click', tokenize);
    // Let parent know we're ready
    postParent('hostedReady', {});
    // Listen for parent's request to tokenize
    window.addEventListener('message', (evt) => {
      if (evt.origin !== 'http://localhost:4242') return;
      if (evt.data && evt.data.type === 'tokenize') tokenize();
    });
  </script>
</body>
</html>
  `);
});

// Vault: tokenize and store minimal card fingerprint (NO raw PAN persistence in demo)
app.post('/vault/tokenize', (req, res) => {
  const { pan, expMonth, expYear } = req.body || {};
  if (!pan || !expMonth || !expYear) return res.status(400).json({ error: 'Missing fields' });

  // Create a random token and store only derived data (last4, brand, expiry)
  const token = 'tok_' + uuid();
  tokens.set(token, {
    last4: maskPAN(pan),
    brand: detectBrand(pan),
    expMonth,
    expYear,
    createdAt: Date.now()
  });

  // IMPORTANT: In a real system, encrypt PAN with a KMS/HSM and store separately in a PCI-scoped vault.
  return res.json({ token });
});

// Payments: authorize (hold), capture (settle), refund
app.post('/payments/authorize', auth, (req, res) => {
  const { amount, paymentToken } = req.body || {};
  const amt = Number(amount);
  if (!Number.isFinite(amt) || amt < 50) return res.status(400).json({ error: 'Invalid amount' });
  if (!tokens.has(paymentToken)) return res.status(400).json({ error: 'Invalid payment token' });

  const fee = computePlatformFee(req.user.role, amt);
  const authorizationId = 'auth_' + uuid();
  authorizations.set(authorizationId, {
    amount: amt,
    token: paymentToken,
    email: req.user.sub,
    fee,
    captured: false,
    refunded: false
  });

  // Simulate risk checks, available balance, etc.
  return res.json({ authorizationId, amount: amt, fee });
});

app.post('/payments/capture', auth, (req, res) => {
  const { authorizationId } = req.body || {};
  const auth = authorizations.get(authorizationId);
  if (!auth) return res.status(404).json({ error: 'Authorization not found' });
  if (auth.captured) return res.status(409).json({ error: 'Already captured' });
  if (auth.refunded) return res.status(409).json({ error: 'Already refunded' });

  auth.captured = true;
  const transactionId = 'txn_' + uuid();
  const settled = true; // Simulate immediate settlement
  transactions.set(transactionId, {
    authId: authorizationId,
    amount: auth.amount,
    fee: auth.fee,
    settled
  });

  // Funds flow (simulated): platform keeps fee, merchant receives amount - fee.
  return res.json({ transactionId, settled, netToMerchant: auth.amount - auth.fee });
});

app.post('/payments/refund', auth, (req, res) => {
  const { authorizationId } = req.body || {};
  const auth = authorizations.get(authorizationId);
  if (!auth) return res.status(404).json({ error: 'Authorization not found' });
  if (!auth.captured) return res.status(409).json({ error: 'Not captured' });
  if (auth.refunded) return res.status(409).json({ error: 'Already refunded' });

  auth.refunded = true;
  const refundId = 'rfnd_' + uuid();
  refunds.set(refundId, { authId: authorizationId, amount: auth.amount });
  return res.json({ refundId });
});

// Health
app.get('/', (_, res) => res.json({ ok: true, service: 'Self-Hosted Payment Gateway API' }));

// Static hosting for client (optional convenience)
app.use(express.static('../client'));

const PORT = process.env.PORT || 4242;
app.listen(PORT, () => console.log(`Server listening on http://localhost:${PORT}`));
