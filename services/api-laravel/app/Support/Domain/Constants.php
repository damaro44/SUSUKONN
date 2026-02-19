<?php

declare(strict_types=1);

namespace App\Support\Domain;

final class Constants
{
    public const APP_NAME = 'SusuKonnect';
    public const TAGLINE = 'Saving Together, Growing Together';

    public const ROLES = ['member', 'leader', 'admin'];
    public const CURRENCIES = ['USD', 'GHS', 'NGN', 'XOF', 'EUR', 'GBP', 'CFA'];
    public const GOVERNMENT_ID_TYPES = ['passport', 'national_id', 'drivers_license'];
    public const MFA_METHODS = ['sms', 'authenticator'];
    public const PAYOUT_REASONS = [
        'College tuition',
        'Wedding',
        'Rent / Housing',
        'Medical procedure',
        'Family vacation',
        'Business investment',
        'Emergency',
        'Custom reason',
    ];

    public const PRIORITY_WEIGHTS = [
        'Emergency' => 100,
        'Medical procedure' => 90,
        'Rent / Housing' => 80,
        'College tuition' => 70,
        'Business investment' => 60,
        'Wedding' => 50,
        'Custom reason' => 45,
        'Family vacation' => 40,
    ];

    public const MFA_REQUIRED_ACTIONS = [
        'login',
        'contribution_pay',
        'payout_approve',
        'payout_release',
        'payment_method_update',
        'security_change',
    ];
}
