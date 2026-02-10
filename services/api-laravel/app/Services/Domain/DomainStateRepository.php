<?php

declare(strict_types=1);

namespace App\Services\Domain;

final class DomainStateRepository
{
    /** @var array<string,mixed>|null */
    private static ?array $state = null;

    /**
     * @return array<string,mixed>
     */
    public function get(): array
    {
        if (self::$state === null) {
            self::$state = SeedStateFactory::make();
        }

        return self::$state;
    }

    /**
     * @param array<string,mixed> $state
     */
    public function set(array $state): void
    {
        self::$state = $state;
    }

    public function reset(): void
    {
        self::$state = SeedStateFactory::make();
    }
}
