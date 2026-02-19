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

    /**
     * @param array{
     *   userId:string,
     *   fullName:string,
     *   dob:string,
     *   idType:string,
     *   idNumber:string,
     *   selfieToken:string,
     *   livenessToken:string,
     *   address:?string
     * } $payload
     * @return array{
     *   provider:string,
     *   referenceId:string,
     *   mode:string,
     *   idDocumentVerified:bool,
     *   livenessVerified:bool,
     *   nameDobVerified:bool,
     *   addressVerified:bool
     * }
     */
    public function verifyIdentity(array $payload): array;
}
