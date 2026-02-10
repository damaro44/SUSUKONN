<?php

declare(strict_types=1);

namespace App\Policies;

final class GroupPolicy
{
    /**
     * @param mixed $user
     * @param array<string,mixed> $group
     */
    public function manage(mixed $user, array $group): bool
    {
        if (is_array($user)) {
            return ($user['role'] ?? null) === 'admin' || ($user['id'] ?? null) === ($group['leaderId'] ?? null);
        }
        if (is_object($user) && property_exists($user, 'id') && property_exists($user, 'role')) {
            return (string) $user->role === 'admin' || (string) $user->id === (string) ($group['leaderId'] ?? '');
        }
        return false;
    }
}
