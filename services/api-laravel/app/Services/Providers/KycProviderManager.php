<?php

declare(strict_types=1);

namespace App\Services\Providers;

use App\Support\Domain\Helpers;
use Stripe\StripeClient;

final class KycProviderManager implements KycProviderInterface
{
    private ?StripeClient $stripeClient = null;

    public function __construct()
    {
        $stripeKey = (string) env('STRIPE_SECRET_KEY', '');
        if ($stripeKey !== '') {
            $this->stripeClient = new StripeClient($stripeKey);
        }
    }

    public function createCase(array $payload): array
    {
        if (!Helpers::asBool(env('KYC_LIVE_MODE', false), false)) {
            return [
                'provider' => 'stripe_identity',
                'caseId' => 'sim_kyc_case_' . Helpers::uid('case'),
                'clientSecret' => 'sim_client_secret',
                'mode' => 'simulation',
            ];
        }

        if ($this->stripeClient === null) {
            throw new \RuntimeException('Missing STRIPE_SECRET_KEY for live KYC mode.');
        }

        $session = $this->stripeClient->identity->verificationSessions->create([
            'type' => 'document',
            'metadata' => [
                'userId' => $payload['userId'],
                'fullName' => $payload['fullName'],
                'email' => $payload['email'],
            ],
        ]);

        return [
            'provider' => 'stripe_identity',
            'caseId' => $session->id,
            'clientSecret' => $session->client_secret,
            'mode' => 'live',
        ];
    }
}
