import express from 'express';
import cors from 'cors';
import Stripe from 'stripe';
import { createClient } from '@supabase/supabase-js';
import { generateApiKey, sha256 } from './lib/api-keys.js';

const app = express();
const PORT = parseInt(process.env.PORT || '8080', 10);

// ── Environment ───────────────────────────────────────
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY!;
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET!;
const SUPABASE_URL = process.env.SUPABASE_URL!;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY!;
const STRIPE_PRICE_STARTER = process.env.STRIPE_PRICE_STARTER!;
const STRIPE_PRICE_PRO = process.env.STRIPE_PRICE_PRO!;
const STRIPE_PRICE_SCALE = process.env.STRIPE_PRICE_SCALE!;

const PRICE_MAP: Record<string, string> = {
  starter: STRIPE_PRICE_STARTER,
  pro:     STRIPE_PRICE_PRO,
  scale:   STRIPE_PRICE_SCALE,
};

const PLAN_LIMITS: Record<string, number> = {
  starter: 5000,
  pro:     50000,
  scale:   1000000,
};

const stripe = new Stripe(STRIPE_SECRET_KEY);
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

// ── Middleware ────────────────────────────────────────
app.use(cors());
app.use(express.json());

// ── Health Check (Cloud Run) ──────────────────────────
app.get('/health', (_req, res) => {
  res.json({ status: 'ok', service: 'airlock-api', version: '1.0.0' });
});

// ── Auth Middleware ───────────────────────────────────
async function apiKeyAuth(req: express.Request, res: express.Response, next: express.NextFunction) {
  const header = req.headers['authorization'] || '';
  const token = header.replace(/^Bearer\s+/i, '').trim();

  if (!token) {
    return res.status(401).json({ error: 'Missing API key — include Authorization: Bearer <key>' });
  }

  const keyHash = sha256(token);

  const { data: keyRecord } = await supabase
    .from('api_keys')
    .select('id, subscriber_id, active, subscribers(active, plan, scan_limit, scans_used)')
    .eq('key_hash', keyHash)
    .eq('active', true)
    .single();

  if (!keyRecord) {
    return res.status(401).json({ error: 'Invalid API key' });
  }

  const sub = (keyRecord as any).subscribers;
  if (!sub?.active) {
    return res.status(403).json({ error: 'Subscription is not active' });
  }

  (req as any).apiKeyId = keyRecord.id;
  (req as any).subscriberId = keyRecord.subscriber_id;
  (req as any).plan = sub.plan;
  (req as any).scanLimit = sub.scan_limit;
  (req as any).scansUsed = sub.scans_used;

  next();
}

// ── Stripe Webhook ─────────────────────────────────────
app.post('/api/stripe/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'] as string;
  let event: Stripe.Event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
  } catch (err: any) {
    console.error('Webhook signature verification failed:', err.message);
    return res.status(400).json({ error: 'Invalid signature' });
  }

  switch (event.type) {
    case 'checkout.session.completed': {
      const session = event.data.object as Stripe.Checkout.Session;
      const userId = session.metadata?.user_id;
      const plan = session.metadata?.plan as keyof typeof PLAN_LIMITS;

      if (!userId || !plan) {
        console.error('Missing metadata:', session.id);
        break;
      }

      const scanLimit = PLAN_LIMITS[plan] || 5000;

      const { data: sub, error: subError } = await supabase
        .from('subscribers')
        .upsert(
          {
            email: session.customer_email || '',
            plan,
            stripe_customer_id: session.customer as string,
            stripe_subscription_id: session.subscription as string,
            scan_limit: scanLimit,
            scans_used: 0,
            billing_cycle_start: new Date().toISOString(),
            active: true,
          },
          { onConflict: 'stripe_customer_id' }
        )
        .select('id')
        .single();

      if (subError || !sub) {
        console.error('Failed to create subscriber:', subError);
        break;
      }

      // Generate and store hashed API key
      const { raw, hash, prefix } = generateApiKey();
      await supabase.from('api_keys').insert({
        subscriber_id: sub.id,
        key_hash: hash,
        key_prefix: prefix,
        name: 'default',
        active: true,
      });

      console.log(`[webhook] Subscriber ${sub.id} subscribed to ${plan} — key: ${raw}`);
      break;
    }

    case 'customer.subscription.deleted': {
      const subEvt = event.data.object as Stripe.Subscription;
      await supabase
        .from('subscribers')
        .update({ active: false, scans_used: 0 })
        .eq('stripe_subscription_id', subEvt.id);
      console.log(`[webhook] Subscription cancelled`);
      break;
    }

    case 'invoice.payment_succeeded': {
      const invoice = event.data.object as Stripe.Invoice;
      if (invoice.billing_reason === 'subscription_cycle') {
        await supabase
          .from('subscribers')
          .update({
            scans_used: 0,
            billing_cycle_start: new Date().toISOString(),
          })
          .eq('stripe_subscription_id', invoice.subscription as string);
        console.log(`[webhook] Billing cycle reset`);
      }
      break;
    }
  }

  res.json({ received: true });
});

// ── Checkout ──────────────────────────────────────────
app.post('/api/checkout', async (req, res) => {
  const { plan, user_id } = req.body;

  if (!plan || !user_id) {
    return res.status(400).json({ error: 'Missing plan or user_id' });
  }

  const priceId = PRICE_MAP[plan as keyof typeof PRICE_MAP];
  if (!priceId) {
    return res.status(400).json({ error: 'Invalid plan' });
  }

  const { data: user } = await supabase.from('users').select('email').eq('id', user_id).single();

  const session = await stripe.checkout.sessions.create({
    mode: 'subscription',
    payment_method_types: ['card'],
    customer_email: user?.email,
    line_items: [{ price: priceId, quantity: 1 }],
    success_url: `${process.env.APP_URL}/success?session_id={CHECKOUT_SESSION_ID}`,
    cancel_url: `${process.env.APP_URL}/#pricing`,
    metadata: { user_id, plan },
  });

  res.json({ url: session.url });
});

// ── Customer Portal ───────────────────────────────────
app.post('/api/portal', async (req, res) => {
  const { user_id } = req.body;
  if (!user_id) return res.status(400).json({ error: 'Missing user_id' });

  const { data: user } = await supabase.from('users')
    .select('stripe_customer_id')
    .eq('id', user_id)
    .single();

  if (!user?.stripe_customer_id) {
    return res.status(400).json({ error: 'No subscription found' });
  }

  const portalSession = await stripe.billingPortal.sessions.create({
    customer: user.stripe_customer_id,
    return_url: `${process.env.APP_URL}/account`,
  });

  res.json({ url: portalSession.url });
});

// ── Subscription Status ───────────────────────────────
app.get('/api/subscription', async (req, res) => {
  const userId = req.query.user_id as string;
  if (!userId) return res.status(400).json({ error: 'Missing user_id' });

  const { data: user } = await supabase.from('users')
    .select('subscription_tier, scans_remaining')
    .eq('id', userId)
    .single();

  res.json(user || { subscription_tier: 'free', scans_remaining: 0 });
});

// ── Scan Endpoint (API Key Auth) ──────────────────────
// NOTE: scanner is loaded at runtime via require() to avoid TS module resolution issues
app.post('/api/scan', apiKeyAuth, async (req: express.Request, res: express.Response) => {
  const { url, agent, mission, mode } = req.body as {
    url?: string;
    agent?: string;
    mission?: string;
    mode?: string;
  };

  if (!url) {
    return res.status(400).json({ error: 'url is required' });
  }

  let parsedUrl: URL;
  try {
    parsedUrl = new URL(url);
  } catch {
    return res.status(400).json({ error: 'url must be a valid URL' });
  }

  if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
    return res.status(400).json({ error: 'url must use http or https' });
  }

  const scanLimit = (req as any).scanLimit as number;
  const scansUsed = (req as any).scansUsed as number;

  if (scansUsed >= scanLimit) {
    return res.status(429).json({
      error: 'Monthly scan limit reached',
      plan: (req as any).plan,
      limit: scanLimit,
    });
  }

  const startMs = Date.now();

  try {
    // Scanner resolution: npm (production/Cloud Run) or relative (local dev)
    let scanMod: any;
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      scanMod = await import(require.resolve('@airlock/scanner'));
    } catch {
      const { resolve } = await import('path');
      const scannerPath = resolve(process.cwd(), 'packages/scanner/src/agent-wrapper.js');
      scanMod = await import(`file://${scannerPath}`);
    }
    const scan = scanMod.scan;

    const result = await scan({
      url,
      agent: agent || 'api',
      mission: mission || 'api-scan',
      mode: mode || 'read',
      memoryWrite: false,
    });

    const elapsed = Date.now() - startMs;
    const packet = result.packet;

    // Increment scan count async — ignore errors
    (async () => {
      try {
        await supabase.rpc('increment_scans_used', { sub_id: (req as any).subscriberId });
      } catch { /* fire-and-forget */ }
    })();

    res.writeHead(200, {
      'Content-Type': 'application/json',
      'X-AirLock-Version': '1.0',
      'X-Scan-Id': packet.scan_id,
      'X-Process-Ms': String(elapsed),
    });
    res.end(JSON.stringify({
      ok: true,
      packet,
      meta: {
        scan_id: packet.scan_id,
        page_risk: packet.page_risk,
        trust_level: packet.trust_level,
        scans_used: scansUsed + 1,
        scan_limit: scanLimit,
        process_ms: elapsed,
      },
    }));
  } catch (err: any) {
    console.error(`[scan] Error for ${url}:`, err.message);
    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: false, error: 'Scan failed', detail: err.message, url }));
  }
});

// ── Auth Callback ──────────────────────────────────────
app.get('/api/auth/callback', async (req, res) => {
  const { code, state } = req.query;
  if (code && state) {
    return res.redirect(`${process.env.APP_URL}/account?code=${code}&state=${state}`);
  }
  res.redirect(`${process.env.APP_URL}/login`);
});

app.listen(PORT, () => {
  console.log(`AirLock API running on port ${PORT}`);
  console.log(`  POST /api/scan          — scan with API key auth`);
  console.log(`  POST /api/checkout      — Stripe checkout`);
  console.log(`  POST /api/stripe/webhook — Stripe webhook`);
});
