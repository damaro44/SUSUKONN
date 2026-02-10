<?php

declare(strict_types=1);

namespace App\Support\Domain\Exceptions;

use RuntimeException;

final class DomainHttpException extends RuntimeException
{
    public function __construct(
        private readonly int $status,
        private readonly string $errorCode,
        string $message,
        private readonly mixed $details = null
    ) {
        parent::__construct($message);
    }

    public function status(): int
    {
        return $this->status;
    }

    public function errorCode(): string
    {
        return $this->errorCode;
    }

    public function details(): mixed
    {
        return $this->details;
    }
}
