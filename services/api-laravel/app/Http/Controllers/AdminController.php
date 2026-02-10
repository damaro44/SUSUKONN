<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

final class AdminController extends ApiController
{
    public function overview(Request $request): JsonResponse
    {
        return $this->execute(function () use ($request): array {
            $auth = $this->authContext($request);
            $this->requireRole($auth['user'], ['admin']);
            return $this->engine->adminOverview((string) $auth['user']['id']);
        });
    }

    public function reviewKyc(Request $request, string $userId): JsonResponse
    {
        return $this->execute(function () use ($request, $userId): array {
            $auth = $this->authContext($request);
            $this->requireRole($auth['user'], ['admin']);
            return $this->engine->reviewKyc(
                (string) $auth['user']['id'],
                $userId,
                (string) $request->input('status', '')
            );
        });
    }

    public function createFraudFlag(Request $request): JsonResponse
    {
        return $this->execute(function () use ($request): array {
            $auth = $this->authContext($request);
            $this->requireRole($auth['user'], ['admin']);
            return $this->engine->createFraudFlag((string) $auth['user']['id'], [
                'targetType' => (string) $request->input('targetType', ''),
                'targetId' => (string) $request->input('targetId', ''),
                'reason' => (string) $request->input('reason', ''),
            ]);
        }, 201);
    }

    public function resolveDispute(Request $request, string $disputeId): JsonResponse
    {
        return $this->execute(function () use ($request, $disputeId): array {
            $auth = $this->authContext($request);
            $this->requireRole($auth['user'], ['admin', 'leader']);
            return $this->engine->resolveDispute((string) $auth['user']['id'], $disputeId);
        });
    }

    public function exportReport(Request $request): JsonResponse
    {
        return $this->execute(function () use ($request): array {
            $auth = $this->authContext($request);
            $this->requireRole($auth['user'], ['admin']);
            $format = (string) $request->query('format', 'json');
            return [
                'format' => $format,
                'content' => $this->engine->exportReport((string) $auth['user']['id'], $format),
            ];
        });
    }

    public function exportAudit(Request $request): JsonResponse
    {
        return $this->execute(function () use ($request): array {
            $auth = $this->authContext($request);
            $this->requireRole($auth['user'], ['admin']);
            return [
                'format' => 'json',
                'content' => $this->engine->exportAudit((string) $auth['user']['id']),
            ];
        });
    }
}
