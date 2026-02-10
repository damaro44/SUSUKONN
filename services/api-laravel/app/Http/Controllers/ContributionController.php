<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

final class ContributionController extends ApiController
{
    public function index(Request $request): JsonResponse
    {
        return $this->execute(function () use ($request): array {
            $auth = $this->authContext($request);
            $groupId = $request->query('groupId');
            return $this->engine->listContributions(
                (string) $auth['user']['id'],
                is_string($groupId) ? $groupId : null
            );
        });
    }

    public function pay(Request $request, string $contributionId): JsonResponse
    {
        return $this->execute(function () use ($request, $contributionId): JsonResponse|array {
            $auth = $this->authContext($request);
            $result = $this->engine->payContribution((string) $auth['user']['id'], $contributionId, [
                'methodId' => (string) $request->input('methodId', ''),
                'enableAutoDebit' => (bool) $request->input('enableAutoDebit', false),
                'mfaChallengeId' => $request->input('mfaChallengeId'),
                'mfaCode' => $request->input('mfaCode'),
            ]);
            if (($result['mfaRequired'] ?? false) === true) {
                return response()->json([
                    'error' => [
                        'code' => 'MFA_REQUIRED',
                        'message' => 'MFA verification is required.',
                    ],
                    'data' => $result['challenge'] ?? null,
                ], 428);
            }
            return $result['contribution'] ?? $result;
        });
    }
}
