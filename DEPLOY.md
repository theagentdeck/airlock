# AirLock — Deployment Guide

## What's Deployed

| Component | Where | URL/Location |
|-----------|-------|-------------|
| Landing Page | Cloudflare Pages | https://airlock.codes |
| Auth API | Cloud Run (GCP) | https://airlock-api-muxxcyee4a-uc.a.run.app |
| Supabase | Supabase | `smrivccfqhsqslgxztqe` |

## Architecture

```
airlock.codes (Cloudflare Pages)
  └── POST /api/checkout  →  airlock-api (Cloud Run)
  └── POST /api/portal   →  airlock-api (Cloud Run)
  └── POST /api/scan     →  airlock-api (Cloud Run)
  └── POST /api/stripe/webhook  →  airlock-api (Cloud Run)
  └── GET /api/subscription  →  airlock-api (Cloud Run)

Stripe (checkout, portal, webhooks)
Supabase (user plans, scan history)
```

---

## 1. GitHub Actions Deploy (airlock-api → Cloud Run)

**File:** `.github/workflows/deploy.yml`

The deploy SA (`airlock-deploy@airlock-deployer`) impersonates the runtime SA (`airlock-api-runtime@airlock-scanner`) via `gcloud auth impersonate`.

### Secrets needed in `airlock-deployer` Secret Manager:
- `stripe-secret-key` — Stripe live key
- `stripe-webhook-secret` — Stripe webhook signing secret
- `supabase-url` — Supabase project URL
- `supabase-service-key` — Supabase service role key
- `stripe-price-starter` — Stripe price ID for Starter tier
- `stripe-price-pro` — Stripe price ID for Pro tier
- `stripe-price-scale` — Stripe price ID for Scale tier

### Runtime SA permissions (`airlock-api-runtime@airlock-scanner`):
- `Artifact Registry Reader` — pull container image
- `Secret Manager Secret Accessor` — read secrets from `airlock-scanner`
- `Cloud Run Admin` — accepted as runtime identity

### Deploy SA permissions (`airlock-deploy@airlock-deployer`):
- `Service Account User` on `airlock-api-runtime@airlock-scanner`
- `Artifact Registry Writer` — push images
- `Cloud Run Admin` — deploy

### Cloud Run service:
- Project: `airlock-scanner`
- Region: `us-central1`
- Service: `airlock-api`
- Runtime SA: `airlock-api-runtime@airlock-scanner`

### To redeploy:
```bash
gh workflow run deploy.yml --repo theagentdeck/airlock
```

---

## 2. Stripe Price IDs (not yet wired in)

The price IDs are stored in `airlock-scanner` Secret Manager:
- `stripe-price-starter`
- `stripe-price-pro`
- `stripe-price-scale`

They need to be read at runtime and used when creating checkout sessions. Currently the checkout flow creates sessions but doesn't set a price — the Stripe prices need to be looked up via the API.

**TODO:** Wire price IDs into the `/api/checkout` endpoint.

---

## 3. Supabase Schema (not yet applied)

Dayta has the handoff for applying the DB schema to Supabase.

**Schema location:** `api/supabase/schema.sql`

**TODO:** Apply schema to `smrivccfqhsqslgxztqe` Supabase project.

---

## 4. Landing Page (airlock.codes)

Source: `mmsneaks11-max/airlock` (Cloudflare Pages)

Env vars needed:
- `NEXT_PUBLIC_SUPABASE_URL`
- `NEXT_PUBLIC_SUPABASE_ANON_KEY`
- `NEXT_PUBLIC_API_URL=https://airlock-api-muxxcyee4a-uc.a.run.app`

Pricing links should point to `POST {NEXT_PUBLIC_API_URL}/api/checkout` to initiate Stripe Checkout.

---

## 5. Stripe Webhook (still needs setup)

Endpoint: `POST https://airlock-api-muxxcyee4a-uc.a.run.app/api/stripe/webhook`

Stripe Dashboard > Developers > Webhooks:
- `checkout.session.completed`
- `customer.subscription.deleted`
- `invoice.payment_succeeded`
- `invoice.payment_failed`

---

## Quick Reference

```bash
# Tail Cloud Run logs
gcloud run logs read airlock-api --region=us-central1 --project=airlock-scanner --limit=50

# Redeploy manually
gcloud run deploy airlock-api \
  --image="us-central1-docker.pkg.dev/airlock-scanner/airlock/airlock-api:latest" \
  --region=us-central1 --project=airlock-scanner \
  --service-account=airlock-api-runtime@airlock-scanner.iam.gserviceaccount.com \
  --platform=managed --allow-unauthenticated \
  --port=8080 --memory=1Gi --cpu=2 \
  --min-instances=0 --max-instances=10 --concurrency=80 --timeout=60s

# Check service status
gcloud run services describe airlock-api --region=us-central1 --project=airlock-scanner
```
