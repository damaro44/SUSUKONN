<?php

declare(strict_types=1);

namespace App\Services\Providers;

use App\Support\Domain\Helpers;
use Illuminate\Support\Facades\Http;
use Stripe\StripeClient;

final class PaymentGatewayManager implements PaymentGatewayInterface
{
    private ?StripeClient $stripeClient = null;

    public function __construct()
    {
        $stripeKey = (string) env('STRIPE_SECRET_KEY', '');
        if ($stripeKey !== '') {
            $this->stripeClient = new StripeClient($stripeKey);
        }
    }

    public function chargeContribution(array $payload): array
    {
        if ($payload['paymentMethodType'] === 'paypal') {
            return $this->chargeWithPayPal($payload);
        }

        return $this->chargeWithStripe($payload);
    }

    public function releasePayout(array $payload): array
    {
        if (($payload['payoutChannel'] ?? 'stripe') === 'paypal') {
            return $this->releaseWithPayPal($payload);
        }

        return $this->releaseWithStripe($payload);
    }

    private function chargeWithStripe(array $payload): array
    {
        if (!Helpers::asBool(env('PAYMENTS_LIVE_MODE', false), false)) {
            return [
                'ok' => true,
                'provider' => 'stripe',
                'reference' => 'sim_stripe_charge_' . Helpers::uid('charge'),
                'raw' => ['mode' => 'simulation'],
            ];
        }

        if ($this->stripeClient === null) {
            throw new \RuntimeException('Missing STRIPE_SECRET_KEY for live Stripe mode.');
        }

        $intent = $this->stripeClient->paymentIntents->create([
            'amount' => (int) round(((float) $payload['amount']) * 100),
            'currency' => $this->normalizeCurrency((string) $payload['currency']),
            'payment_method' => (string) $payload['paymentTokenRef'],
            'confirm' => true,
            'automatic_payment_methods' => ['enabled' => false],
            'description' => 'SusuKonnect contribution charge',
            'metadata' => $payload['metadata'] ?? [],
        ]);

        return [
            'ok' => $intent->status === 'succeeded',
            'provider' => 'stripe',
            'reference' => $intent->id,
            'raw' => $intent->toArray(),
        ];
    }

    private function releaseWithStripe(array $payload): array
    {
        if (!Helpers::asBool(env('PAYMENTS_LIVE_MODE', false), false)) {
            return [
                'ok' => true,
                'provider' => 'stripe',
                'reference' => 'sim_stripe_payout_' . Helpers::uid('payout'),
                'raw' => ['mode' => 'simulation'],
            ];
        }

        if ($this->stripeClient === null) {
            throw new \RuntimeException('Missing STRIPE_SECRET_KEY for live Stripe mode.');
        }

        $destination = (string) $payload['destinationTokenRef'];
        if (!str_starts_with($destination, 'acct_')) {
            return [
                'ok' => true,
                'provider' => 'stripe',
                'reference' => 'manual_settlement_' . Helpers::uid('settle'),
                'raw' => ['note' => 'Destination is not connected-account ID; manual fallback used.'],
            ];
        }

        $transfer = $this->stripeClient->transfers->create([
            'amount' => (int) round(((float) $payload['amount']) * 100),
            'currency' => $this->normalizeCurrency((string) $payload['currency']),
            'destination' => $destination,
            'metadata' => $payload['metadata'] ?? [],
            'description' => 'SusuKonnect payout release',
        ]);

        return [
            'ok' => true,
            'provider' => 'stripe',
            'reference' => $transfer->id,
            'raw' => $transfer->toArray(),
        ];
    }

    private function chargeWithPayPal(array $payload): array
    {
        if (!Helpers::asBool(env('PAYMENTS_LIVE_MODE', false), false)) {
            return [
                'ok' => true,
                'provider' => 'paypal',
                'reference' => 'sim_paypal_charge_' . Helpers::uid('charge'),
                'raw' => ['mode' => 'simulation'],
            ];
        }

        $token = $this->paypalAccessToken();
        $baseUrl = rtrim((string) env('PAYPAL_BASE_URL', 'https://api-m.sandbox.paypal.com'), '/');
        $currency = strtoupper($this->normalizeCurrency((string) $payload['currency']));

        $orderCreate = Http::withToken($token)
            ->acceptJson()
            ->post($baseUrl . '/v2/checkout/orders', [
                'intent' => 'CAPTURE',
                'purchase_units' => [[
                    'amount' => [
                        'currency_code' => $currency,
                        'value' => number_format((float) $payload['amount'], 2, '.', ''),
                    ],
                ]],
            ])
            ->throw()
            ->json();

        $orderId = (string) ($orderCreate['id'] ?? '');

        $capture = Http::withToken($token)
            ->acceptJson()
            ->post($baseUrl . '/v2/checkout/orders/' . $orderId . '/capture')
            ->throw()
            ->json();

        return [
            'ok' => ($capture['status'] ?? '') === 'COMPLETED',
            'provider' => 'paypal',
            'reference' => $orderId,
            'raw' => $capture,
        ];
    }

    private function releaseWithPayPal(array $payload): array
    {
        if (!Helpers::asBool(env('PAYMENTS_LIVE_MODE', false), false)) {
            return [
                'ok' => true,
                'provider' => 'paypal',
                'reference' => 'sim_paypal_payout_' . Helpers::uid('payout'),
                'raw' => ['mode' => 'simulation'],
            ];
        }

        $token = $this->paypalAccessToken();
        $baseUrl = rtrim((string) env('PAYPAL_BASE_URL', 'https://api-m.sandbox.paypal.com'), '/');
        $currency = strtoupper($this->normalizeCurrency((string) $payload['currency']));

        $response = Http::withToken($token)
            ->acceptJson()
            ->post($baseUrl . '/v1/payments/payouts', [
                'sender_batch_header' => [
                    'sender_batch_id' => Helpers::uid('batch'),
                    'email_subject' => 'You have a payout from SusuKonnect',
                ],
                'items' => [[
                    'recipient_type' => 'EMAIL',
                    'amount' => [
                        'value' => number_format((float) $payload['amount'], 2, '.', ''),
                        'currency' => $currency,
                    ],
                    'receiver' => (string) $payload['recipientEmail'],
                    'note' => 'SusuKonnect payout release',
                    'sender_item_id' => Helpers::uid('item'),
                ]],
            ])
            ->throw()
            ->json();

        return [
            'ok' => true,
            'provider' => 'paypal',
            'reference' => (string) ($response['batch_header']['payout_batch_id'] ?? Helpers::uid('paypal_batch')),
            'raw' => $response,
        ];
    }

    private function paypalAccessToken(): string
    {
        $clientId = (string) env('PAYPAL_CLIENT_ID', '');
        $clientSecret = (string) env('PAYPAL_CLIENT_SECRET', '');
        if ($clientId === '' || $clientSecret === '') {
            throw new \RuntimeException('Missing PayPal credentials.');
        }

        $baseUrl = rtrim((string) env('PAYPAL_BASE_URL', 'https://api-m.sandbox.paypal.com'), '/');
        $response = Http::withHeaders([
            'Authorization' => 'Basic ' . base64_encode($clientId . ':' . $clientSecret),
            'Content-Type' => 'application/x-www-form-urlencoded',
        ])->asForm()
            ->post($baseUrl . '/v1/oauth2/token', ['grant_type' => 'client_credentials'])
            ->throw()
            ->json();

        return (string) ($response['access_token'] ?? '');
    }

    private function normalizeCurrency(string $currency): string
    {
        $candidate = strtolower(trim($currency));
        if ($candidate === 'xof' || $candidate === 'cfa') {
            return 'eur';
        }
        if (strlen($candidate) !== 3) {
            return 'usd';
        }
        return $candidate;
    }
}
