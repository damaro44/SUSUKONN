<?php

declare(strict_types=1);

namespace App\Services\Providers;

interface PaymentGatewayInterface
{
    /**
     * @param array{
     *   amount:float,
     *   currency:string,
     *   paymentMethodType:string,
     *   paymentTokenRef:string,
     *   metadata?:array<string,string>
     * } $payload
     *
     * @return array{ok:bool,provider:string,reference:string,raw:mixed}
     */
    public function chargeContribution(array $payload): array;

    /**
     * @param array{
     *   amount:float,
     *   currency:string,
     *   payoutChannel:string,
     *   destinationTokenRef:string,
     *   recipientEmail:string,
     *   metadata?:array<string,string>
     * } $payload
     *
     * @return array{ok:bool,provider:string,reference:string,raw:mixed}
     */
    public function releasePayout(array $payload): array;
}
