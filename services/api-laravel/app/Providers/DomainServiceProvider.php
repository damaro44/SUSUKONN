<?php

declare(strict_types=1);

namespace App\Providers;

use App\Services\Domain\DomainEngineService;
use App\Services\Domain\DomainStateRepository;
use App\Services\Providers\KycProviderManager;
use App\Services\Providers\PaymentGatewayManager;
use Illuminate\Support\ServiceProvider;

final class DomainServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(DomainStateRepository::class, static fn (): DomainStateRepository => new DomainStateRepository());
        $this->app->singleton(PaymentGatewayManager::class, static fn (): PaymentGatewayManager => new PaymentGatewayManager());
        $this->app->singleton(KycProviderManager::class, static fn (): KycProviderManager => new KycProviderManager());
        $this->app->singleton(
            DomainEngineService::class,
            static fn ($app): DomainEngineService => new DomainEngineService(
                $app->make(DomainStateRepository::class),
                $app->make(PaymentGatewayManager::class),
                $app->make(KycProviderManager::class)
            )
        );
    }
}
