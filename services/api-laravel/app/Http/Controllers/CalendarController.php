<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

final class CalendarController extends ApiController
{
    public function index(Request $request): JsonResponse
    {
        return $this->execute(function () use ($request): array {
            $auth = $this->authContext($request);
            return $this->engine->calendarEvents((string) $auth['user']['id']);
        });
    }
}
