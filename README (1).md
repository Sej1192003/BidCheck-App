# BidCheck App

AI-powered contractor quote auditor. Upload a photo, get a full audit in seconds.

## Environment Variables (set in Railway)

| Variable | Description |
|---|---|
| `ANTHROPIC_API_KEY` | Your Anthropic API key |
| `STRIPE_SECRET_KEY` | Stripe secret key (sk_test_...) |
| `STRIPE_PRICE_ID` | Stripe price ID (price_...) |
| `STRIPE_WEBHOOK_SECRET` | Stripe webhook secret (set up after deploy) |
| `SECRET_KEY` | Any random string for JWT signing |

## Stack
- Python / Flask backend
- SQLite database
- Claude API for quote analysis
- Stripe for subscriptions
- Vanilla JS frontend
