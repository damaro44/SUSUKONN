<?php

declare(strict_types=1);

namespace App\Support\Domain;

use App\Support\Domain\Exceptions\DomainHttpException;
use DateInterval;
use DateTimeImmutable;

final class Helpers
{
    public static function assert(bool $condition, int $status, string $code, string $message, mixed $details = null): void
    {
        if (!$condition) {
            throw new DomainHttpException($status, $code, $message, $details);
        }
    }

    public static function uid(string $prefix): string
    {
        return $prefix . '_' . bin2hex(random_bytes(6)) . '_' . base_convert((string) microtime(true), 10, 36);
    }

    public static function nowIso(): string
    {
        return (new DateTimeImmutable('now'))->format(DATE_ATOM);
    }

    public static function addMinutes(string $iso, int $minutes): string
    {
        $dt = new DateTimeImmutable($iso);
        return $dt->add(new DateInterval('PT' . $minutes . 'M'))->format(DATE_ATOM);
    }

    public static function addHours(string $iso, int $hours): string
    {
        $dt = new DateTimeImmutable($iso);
        return $dt->add(new DateInterval('PT' . $hours . 'H'))->format(DATE_ATOM);
    }

    public static function normalizeEmail(string $value): string
    {
        return strtolower(trim($value));
    }

    public static function normalizePhone(string $value): string
    {
        return trim((string) preg_replace('/[^\d+]/', '', $value));
    }

    public static function hashValue(string $value): string
    {
        return hash('sha256', $value);
    }

    public static function hashPassword(string $password, string $salt): string
    {
        return self::hashValue($salt . ':' . $password);
    }

    public static function tokenRef(string $value): string
    {
        return 'tok_' . substr(self::hashValue($value), 0, 28);
    }

    public static function generateMfaCode(): string
    {
        return (string) random_int(100000, 999999);
    }

    public static function cycleDueDate(string $startDate, int $cycle): string
    {
        $date = new DateTimeImmutable($startDate . 'T00:00:00+00:00');
        return $date->modify('+' . max(0, $cycle - 1) . ' month')->format(DATE_ATOM);
    }

    public static function cycleGraceDate(string $startDate, int $cycle, int $graceDays): string
    {
        $dueDate = new DateTimeImmutable(self::cycleDueDate($startDate, $cycle));
        return $dueDate->modify('+' . max(0, $graceDays) . ' day')->format(DATE_ATOM);
    }

    public static function roundTwo(float $value): float
    {
        return round($value, 2);
    }

    public static function asBool(mixed $value, bool $default = false): bool
    {
        if ($value === null) {
            return $default;
        }
        if (is_bool($value)) {
            return $value;
        }
        if (is_string($value)) {
            return strtolower($value) === 'true' || $value === '1';
        }
        if (is_int($value)) {
            return $value === 1;
        }
        return $default;
    }
}
