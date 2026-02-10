<?php

declare(strict_types=1);

namespace App\Services\Providers;

interface KycProviderInterface
{
    /**
     * @param array{userId:string,fullName:string,email:string} $payload
     * @return array{provider:string,caseId:string,clientSecret:?string,mode:string}
     */
    public function createCase(array $payload): array;
}
