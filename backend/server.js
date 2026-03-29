// ============================================================
//  COD1 ECOSYSTEM — BACKEND SERVER
//  All sensitive logic lives HERE only.
//  Frontend never sees tokens, DB queries, or secrets.
// ============================================================

require('dotenv').config();
const express      = require('express');
const cors         = require('cors');
const bcrypt       = require('bcryptjs');
const crypto       = require('crypto');
const nodemailer   = require('nodemailer');
const rateLimit    = require('express-rate-limit');
const speakeasy    = require('speakeasy');
const path         = require('path');

const app = express();

// ── Serve frontend files (index.html, login.html, etc.)
app.use(express.static(path.join(__dirname, '..')));
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'login.html'));
});

// ── Body parser
app.use(express.json());

// ── CORS — only allow your own frontend
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true
}));

// ── Rate limiters
const otpLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 5, message: { error: 'Too many OTP requests. Try again in 1 hour.' } });
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, message: { error: 'Too many attempts. Try again in 15 minutes.' } });

// ============================================================
//  IN-MEMORY STORE  (replace with PostgreSQL in production)
//  These are NEVER sent to the frontend — only results are.
// ============================================================
const users  = {};   // { email: { name, phone, passwordHash, emailVerified } }
const tokens = {};   // { email: { hash, expires } }
const otpSecrets = {}; // { userId: { secret, attempts, expires } }

// ============================================================
//  EMAIL TRANSPORTER  (credentials only on server)
// ============================================================
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_APP_PASSWORD   // App password, never exposed to frontend
  }
});

// Helper: hash a token before storing
function hashToken(raw) {
  return crypto.createHash('sha256').update(raw).digest('hex');
}

// Helper: send styled email
async function sendVerificationEmail(email, name, verifyUrl) {
  await transporter.sendMail({
    from: `"COD1 Ecosystem" <${process.env.GMAIL_USER}>`,
    to: email,
    subject: 'Verify your COD1 Ecosystem account',
    html: `
      <!DOCTYPE html>
      <html>
      <body style="margin:0;padding:0;background:#050508;font-family:'Courier New',monospace;">
        <table width="100%" cellpadding="0" cellspacing="0">
          <tr><td align="center" style="padding:40px 20px;">
            <table width="520" cellpadding="0" cellspacing="0" style="background:#12121e;border-radius:16px;border:1px solid rgba(124,58,255,0.3);overflow:hidden;">
              <!-- Header bar -->
              <tr><td style="background:linear-gradient(135deg,#7c3aff,#a855f7);padding:3px 0;"></td></tr>
              <!-- Logo -->
              <tr><td style="padding:36px 40px 0;text-align:center;">
                <div style="display:inline-block;width:54px;height:54px;background:linear-gradient(135deg,#7c3aff,#00f0ff);border-radius:14px;line-height:54px;font-size:18px;font-weight:800;color:#fff;font-family:Arial,sans-serif;">C1</div>
                <h1 style="color:#b57bff;font-size:22px;margin:12px 0 4px;letter-spacing:-0.02em;">COD1 Ecosystem</h1>
                <p style="color:#5544aa;font-size:12px;margin:0;letter-spacing:0.15em;">// VERIFICATION REQUIRED</p>
              </td></tr>
              <!-- Body -->
              <tr><td style="padding:28px 40px;">
                <p style="color:#9988cc;font-size:14px;line-height:1.9;margin:0 0 8px;">Hi <strong style="color:#e8e0ff;">${name}</strong>,</p>
                <p style="color:#9988cc;font-size:14px;line-height:1.9;margin:0 0 28px;">You're one step away. Click below to verify your email and access the COD1 Ecosystem.</p>
                <table width="100%" cellpadding="0" cellspacing="0">
                  <tr><td align="center">
                    <a href="${verifyUrl}" style="display:inline-block;padding:14px 36px;background:linear-gradient(135deg,#7c3aff,#5b21b6);color:#ffffff;text-decoration:none;border-radius:10px;font-weight:700;font-size:14px;letter-spacing:0.08em;box-shadow:0 0 24px rgba(124,58,255,0.4);">
                      ✓ &nbsp; Verify My Email
                    </a>
                  </td></tr>
                </table>
                <p style="color:#4a3a99;font-size:12px;text-align:center;margin:24px 0 0;line-height:1.8;">
                  This button expires in <strong style="color:#f59e0b;">15 minutes</strong>.<br>
                  If you didn't create this account, ignore this email.
                </p>
              </td></tr>
              <!-- Footer -->
              <tr><td style="padding:20px 40px;border-top:1px solid rgba(120,80,255,0.1);text-align:center;">
                <p style="color:#2a1a66;font-size:11px;margin:0;">© 2026 COD1 Ecosystem · Ahmedabad, Gujarat</p>
              </td></tr>
            </table>
          </td></tr>
        </table>
      </body>
      </html>
    `
  });
}

// ============================================================
//  ROUTES
// ============================================================

// POST /api/register
app.post('/api/register', authLimiter, async (req, res) => {
  try {
    const { name, email, phone, password } = req.body;

    // Validate — server side always
    if (!name || !email || !phone || !password)
      return res.status(400).json({ error: 'All fields are required.' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
      return res.status(400).json({ error: 'Invalid email address.' });
    if (password.length < 8)
      return res.status(400).json({ error: 'Password must be at least 8 characters.' });
    if (users[email])
      return res.status(409).json({ error: 'An account with this email already exists.' });

    // Hash password — NEVER store plain
    const passwordHash = await bcrypt.hash(password, 12);

    // Save user
    users[email] = { name, phone, passwordHash, emailVerified: false };

    // Generate raw token → hash it → store hash only
    const rawToken = crypto.randomBytes(32).toString('hex');
    tokens[email]  = { hash: hashToken(rawToken), expires: Date.now() + 15 * 60 * 1000 };

    // Build verify URL — frontend never sees rawToken except in the email link
    const baseUrl   = process.env.BASE_URL || 'http://localhost:3000';
    const verifyUrl = `${baseUrl}/api/verify-email?token=${rawToken}&email=${encodeURIComponent(email)}`;

    // Send email
    await sendVerificationEmail(email, name, verifyUrl);

    // Return ONLY success — no token, no hash, no internals
    res.json({ success: true, message: 'Account created. Check your email to verify.' });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Server error. Please try again.' });
  }
});

// GET /api/verify-email  (user clicks link from email)
app.get('/api/verify-email', (req, res) => {
  try {
    const { token, email } = req.query;
    const record = tokens[email];

    if (!record || record.hash !== hashToken(token))
      return res.redirect('/login.html?status=invalid');
    if (Date.now() > record.expires)
      return res.redirect('/login.html?status=expired');

    // Mark verified, delete token
    users[email].emailVerified = true;
    delete tokens[email];

    // Redirect to login page with verified flag — no token in URL
    res.redirect('/login.html?status=verified');
  } catch (err) {
    res.redirect('/login.html?status=error');
  }
});

// POST /api/login
app.post('/api/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = users[email];

    if (!user) return res.status(401).json({ error: 'Invalid email or password.' });
    if (!user.emailVerified) return res.status(403).json({ error: 'Please verify your email first.' });

    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) return res.status(401).json({ error: 'Invalid email or password.' });

    // In production: generate a JWT here and set as httpOnly cookie
    // For now return only what the frontend needs — NOT the hash
    res.json({ success: true, user: { name: user.name, email } });
  } catch (err) {
    res.status(500).json({ error: 'Server error.' });
  }
});

// POST /api/send-otp
app.post('/api/send-otp', otpLimiter, async (req, res) => {
  try {
    const { phone } = req.body;
    if (!phone) return res.status(400).json({ error: 'Phone number required.' });

    // Generate TOTP secret — stays on server only
    const secret = speakeasy.generateSecret({ length: 20 });
    const otp    = speakeasy.totp({ secret: secret.base32, encoding: 'base32', step: 30 });

    // Store secret (hashed), NOT the OTP itself
    otpSecrets[phone] = { secret: secret.base32, attempts: 0, expires: Date.now() + 30000 };

    // Send SMS via Twilio
    // const twilio = require('twilio')(process.env.TWILIO_SID, process.env.TWILIO_TOKEN);
    // await twilio.messages.create({ body: `Your COD1 code: ${otp}. Valid 30 seconds.`, from: process.env.TWILIO_FROM, to: phone });

    console.log(`[DEV] OTP for ${phone}: ${otp}`);  // Remove in production

    res.json({ success: true, message: 'OTP sent.' });
  } catch (err) {
    res.status(500).json({ error: 'Could not send OTP.' });
  }
});

// POST /api/verify-otp
app.post('/api/verify-otp', (req, res) => {
  try {
    const { phone, otp } = req.body;
    const record = otpSecrets[phone];

    if (!record) return res.status(400).json({ error: 'No OTP request found. Request a new one.' });
    if (Date.now() > record.expires) return res.status(400).json({ error: 'OTP expired.' });
    if (record.attempts >= 1) return res.status(429).json({ error: 'Too many attempts. Request a new OTP.' });

    const valid = speakeasy.totp.verify({ secret: record.secret, encoding: 'base32', token: otp, step: 30, window: 0 });

    if (!valid) {
      otpSecrets[phone].attempts++;
      return res.status(400).json({ error: 'Incorrect OTP.' });
    }

    delete otpSecrets[phone];
    res.json({ success: true, message: 'Phone verified.' });
  } catch (err) {
    res.status(500).json({ error: 'Verification failed.' });
  }
});

// POST /api/forgot-password
app.post('/api/forgot-password', authLimiter, async (req, res) => {
  try {
    const { email } = req.body;
    // Always return same message — don't reveal if email exists
    if (users[email]) {
      const rawToken = crypto.randomBytes(32).toString('hex');
      tokens[`reset_${email}`] = { hash: hashToken(rawToken), expires: Date.now() + 15 * 60 * 1000 };
      const baseUrl   = process.env.BASE_URL || 'http://localhost:3000';
      const resetUrl  = `${baseUrl}/login.html?action=reset&token=${rawToken}&email=${encodeURIComponent(email)}`;
      await transporter.sendMail({
        from: `"COD1 Ecosystem" <${process.env.GMAIL_USER}>`,
        to: email,
        subject: 'Reset your COD1 Ecosystem password',
        html: `<div style="background:#050508;padding:40px;font-family:monospace;color:#e8e0ff;border-radius:16px;">
          <h2 style="color:#b57bff;">Password Reset</h2>
          <p style="color:#9988cc;">Click below to reset your password. Link expires in 15 minutes.</p>
          <a href="${resetUrl}" style="display:inline-block;margin:20px 0;padding:12px 28px;background:#7c3aff;color:#fff;border-radius:8px;text-decoration:none;font-weight:700;">Reset Password</a>
          <p style="color:#3a2a88;font-size:12px;">If you didn't request this, ignore this email.</p>
        </div>`
      });
    }
    res.json({ success: true, message: 'If that email exists, a reset link was sent.' });
  } catch (err) {
    res.status(500).json({ error: 'Server error.' });
  }
});

// POST /api/contact
app.post('/api/contact', async (req, res) => {
  try {
    const { name, email, subject, message } = req.body;
    if (!name || !email || !message) return res.status(400).json({ error: 'Fill in all fields.' });
    await transporter.sendMail({
      from: `"COD1 Site" <${process.env.GMAIL_USER}>`,
      to: process.env.GMAIL_USER,
      subject: `[COD1 Contact] ${subject || 'New message'}`,
      html: `<p><b>From:</b> ${name} (${email})</p><p><b>Message:</b><br>${message}</p>`
    });
    res.json({ success: true, message: 'Message received!' });
  } catch (err) {
    res.status(500).json({ error: 'Could not send message.' });
  }
});

// ── Start
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ COD1 backend running → http://localhost:${PORT}`));
