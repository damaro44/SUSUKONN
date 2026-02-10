<?php

declare(strict_types=1);

namespace App\Policies;

final class AdminPolicy
{
    public function admin(mixed $user): bool
    {
        if (is_array($user)) {
            return ($user['role'] ?? null) === 'admin';
        }
        if (is_object($user) && property_exists($user, 'role')) {
            return (string) $user->role === 'admin';
        }
        return false;
    }
}
