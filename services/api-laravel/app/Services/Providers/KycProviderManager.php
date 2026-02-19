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

    public function verifyIdentity(array $payload): array
    {
        $fullName = trim((string) ($payload['fullName'] ?? ''));
        $dob = trim((string) ($payload['dob'] ?? ''));
        $idNumber = trim((string) ($payload['idNumber'] ?? ''));
        $livenessToken = trim((string) ($payload['livenessToken'] ?? ''));
        $address = trim((string) ($payload['address'] ?? ''));
        $nameParts = array_values(array_filter(preg_split('/\s+/', $fullName) ?: [], static fn (string $part): bool => $part !== ''));

        $idDocumentVerified = strlen($idNumber) >= 4;
        $livenessVerified = strlen($livenessToken) >= 6;
        $nameDobVerified = count($nameParts) >= 2 && $this->isIsoDate($dob);
        $addressVerified = $address !== '' && strlen($address) >= 8;
        $mode = Helpers::asBool(env('KYC_LIVE_MODE', false), false) ? 'live' : 'simulation';

        return [
            'provider' => 'stripe_identity',
            'referenceId' => ($mode === 'live' ? 'live_kyc_verify_' : 'sim_kyc_verify_') . Helpers::uid('verify'),
            'mode' => $mode,
            'idDocumentVerified' => $idDocumentVerified,
            'livenessVerified' => $livenessVerified,
            'nameDobVerified' => $nameDobVerified,
            'addressVerified' => $addressVerified,
        ];
    }

    private function isIsoDate(string $value): bool
    {
        if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $value)) {
            return false;
        }
        $parsed = strtotime($value);
        return $parsed !== false;
    }
}
