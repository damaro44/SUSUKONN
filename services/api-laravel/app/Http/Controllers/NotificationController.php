<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

final class NotificationController extends ApiController
{
    public function index(Request $request): JsonResponse
    {
        return $this->execute(function () use ($request): array {
            $auth = $this->authContext($request);
            return $this->engine->userNotifications((string) $auth['user']['id']);
        });
    }

    public function markRead(Request $request, string $notificationId): JsonResponse
    {
        return $this->execute(function () use ($request, $notificationId): null {
            $auth = $this->authContext($request);
            $this->engine->markNotificationRead((string) $auth['user']['id'], $notificationId);
            return null;
        }, 204);
    }

    public function markAllRead(Request $request): JsonResponse
    {
        return $this->execute(function () use ($request): null {
            $auth = $this->authContext($request);
            $this->engine->markAllNotificationsRead((string) $auth['user']['id']);
            return null;
        }, 204);
    }
}
