<?php

namespace App\Http\Controllers;

use Illuminate\Http\JsonResponse;

class ScaffoldController extends Controller
{
    protected function notImplemented(string $method): JsonResponse
    {
        return response()->json([
            'error' => [
                'code' => 'NOT_IMPLEMENTED',
                'message' => "Laravel scaffold method '{$method}' is not implemented yet.",
            ],
        ], 501);
    }
}
