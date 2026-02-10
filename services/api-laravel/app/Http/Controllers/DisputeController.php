<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

final class DisputeController extends ApiController
{
    public function store(Request $request): JsonResponse
    {
        return $this->execute(fn () => $this->engine->submitDispute(
            (string) $this->authContext($request)['user']['id'],
            (string) $request->input('groupId', ''),
            (string) $request->input('summary', '')
        ), 201);
    }
}
