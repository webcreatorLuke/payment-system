const db = require('./db');

// Seed owner
(function ensureOwner() {
  const email = process.env.OWNER_EMAIL;
  if (!email) return;
  db.get('SELECT email FROM users WHERE email=?', [email], (err, row) => {
    if (err) return console.error(err);
    if (!row) {
      const hash = bcrypt.hashSync('change_this_owner_password', 10);
      db.run('INSERT INTO users(email, password_hash, role) VALUES(?,?,?)', [email, hash, 'owner']);
    }
  });
})();

// Signup
app.post('/auth/signup', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  db.get('SELECT email FROM users WHERE email=?', [email], async (err, row) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (row) return res.status(409).json({ error: 'Email already exists' });
    const role = email === process.env.OWNER_EMAIL ? 'owner' : 'merchant';
    const hash = await bcrypt.hash(password, 10);
    db.run('INSERT INTO users(email, password_hash, role) VALUES(?,?,?)', [email, hash, role], (e) => {
      if (e) return res.status(500).json({ error: 'DB error' });
      res.json({ ok: true });
    });
  });
});

// Login
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  db.get('SELECT email, password_hash, role FROM users WHERE email=?', [email], async (err, u) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!u) return res.status(404).json({ error: 'User not found' });
    const ok = await bcrypt.compare(password, u.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    const token = signToken({ email: u.email, role: u.role });
    res.json({ token, user: { email: u.email, role: u.role } });
  });
});

// Vault: save token
app.post('/vault/tokenize', (req, res) => {
  const { pan, expMonth, expYear } = req.body || {};
  if (!pan || !expMonth || !expYear) return res.status(400).json({ error: 'Missing fields' });
  const token = 'tok_' + uuid();
  const last4 = maskPAN(pan);
  const brand = detectBrand(pan);
  const createdAt = Date.now();
  db.run(
    'INSERT INTO tokens(token, last4, brand, exp_month, exp_year, created_at) VALUES(?,?,?,?,?,?)',
    [token, last4, brand, expMonth, expYear, createdAt],
    (e) => {
      if (e) return res.status(500).json({ error: 'DB error' });
      res.json({ token });
    }
  );
});

// Authorize
app.post('/payments/authorize', auth, (req, res) => {
  const { amount, paymentToken } = req.body || {};
  const amt = Number(amount);
  if (!Number.isFinite(amt) || amt < 50) return res.status(400).json({ error: 'Invalid amount' });

  db.get('SELECT token FROM tokens WHERE token=?', [paymentToken], (e, t) => {
    if (e) return res.status(500).json({ error: 'DB error' });
    if (!t) return res.status(400).json({ error: 'Invalid payment token' });

    const fee = computePlatformFee(req.user.role, amt);
    const id = 'auth_' + uuid();
    db.run(
      'INSERT INTO authorizations(id, amount, token, email, fee, captured, refunded) VALUES(?,?,?,?,?,?,?)',
      [id, amt, paymentToken, req.user.sub, fee, 0, 0],
      (err2) => {
        if (err2) return res.status(500).json({ error: 'DB error' });
        res.json({ authorizationId: id, amount: amt, fee });
      }
    );
  });
});

// Capture
app.post('/payments/capture', auth, (req, res) => {
  const { authorizationId } = req.body || {};
  db.get('SELECT * FROM authorizations WHERE id=?', [authorizationId], (e, authRow) => {
    if (e) return res.status(500).json({ error: 'DB error' });
    if (!authRow) return res.status(404).json({ error: 'Authorization not found' });
    if (authRow.captured) return res.status(409).json({ error: 'Already captured' });
    if (authRow.refunded) return res.status(409).json({ error: 'Already refunded' });

    db.run('UPDATE authorizations SET captured=1 WHERE id=?', [authorizationId], (e2) => {
      if (e2) return res.status(500).json({ error: 'DB error' });
      const txnId = 'txn_' + uuid();
      db.run(
        'INSERT INTO transactions(id, auth_id, amount, fee, settled) VALUES(?,?,?,?,?)',
        [txnId, authorizationId, authRow.amount, authRow.fee, 1],
        (e3) => {
          if (e3) return res.status(500).json({ error: 'DB error' });
          res.json({ transactionId: txnId, settled: true, netToMerchant: authRow.amount - authRow.fee });
        }
      );
    });
  });
});

// Refund
app.post('/payments/refund', auth, (req, res) => {
  const { authorizationId } = req.body || {};
  db.get('SELECT * FROM authorizations WHERE id=?', [authorizationId], (e, authRow) => {
    if (e) return res.status(500).json({ error: 'DB error' });
    if (!authRow) return res.status(404).json({ error: 'Authorization not found' });
    if (!authRow.captured) return res.status(409).json({ error: 'Not captured' });
    if (authRow.refunded) return res.status(409).json({ error: 'Already refunded' });

    const refundId = 'rfnd_' + uuid();
    db.run('UPDATE authorizations SET refunded=1 WHERE id=?', [authorizationId], (e2) => {
      if (e2) return res.status(500).json({ error: 'DB error' });
      db.run('INSERT INTO refunds(id, auth_id, amount) VALUES(?,?,?)', [refundId, authorizationId, authRow.amount], (e3) => {
        if (e3) return res.status(500).json({ error: 'DB error' });
        res.json({ refundId });
      });
    });
  });
});
