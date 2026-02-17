<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

final class ChatController extends ApiController
{
    public function index(Request $request, string $groupId): JsonResponse
    {
        return $this->execute(function () use ($request, $groupId): array {
            $auth = $this->authContext($request);
            return $this->engine->listChat((string) $auth['user']['id'], $groupId);
        });
    }

    public function store(Request $request, string $groupId): JsonResponse
    {
        return $this->execute(function () use ($request, $groupId): array {
            $auth = $this->authContext($request);
            return $this->engine->sendChat((string) $auth['user']['id'], $groupId, [
                'content' => (string) $request->input('content', ''),
                'announcement' => (bool) $request->input('announcement', false),
                'pin' => (bool) $request->input('pin', false),
            ]);
        }, 201);
    }

    public function togglePin(Request $request, string $messageId): JsonResponse
    {
        return $this->execute(function () use ($request, $messageId): array {
            $auth = $this->authContext($request);
            return $this->engine->togglePin((string) $auth['user']['id'], $messageId);
        });
    }

    public function destroy(Request $request, string $messageId): JsonResponse
    {
        return $this->execute(function () use ($request, $messageId): array {
            $auth = $this->authContext($request);
            return $this->engine->deleteChatMessage((string) $auth['user']['id'], $messageId);
        });
    }
}
