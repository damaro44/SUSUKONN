<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

final class DashboardController extends ApiController
{
    public function index(Request $request): JsonResponse
    {
        return $this->execute(function () use ($request): array {
            $auth = $this->authContext($request);
            return $this->engine->dashboard((string) $auth['user']['id']);
        });
    }
}
