<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

final class PayoutController extends ApiController
{
    public function index(Request $request): JsonResponse
    {
        return $this->execute(function () use ($request): array {
            $auth = $this->authContext($request);
            $groupId = $request->query('groupId');
            return $this->engine->listPayouts((string) $auth['user']['id'], is_string($groupId) ? $groupId : null);
        });
    }

    public function request(Request $request, string $groupId): JsonResponse
    {
        return $this->execute(fn () => $this->engine->requestPayout(
            (string) $this->authContext($request)['user']['id'],
            $groupId,
            (string) $request->input('reason', ''),
            $request->input('customReason')
        ), 201);
    }

    public function vote(Request $request, string $groupId): JsonResponse
    {
        return $this->execute(function () use ($request, $groupId): array {
            $auth = $this->authContext($request);
            $this->engine->submitVote(
                (string) $auth['user']['id'],
                $groupId,
                (string) $request->input('candidateId', ''),
                $request->input('note')
            );
            return ['ok' => true];
        }, 201);
    }

    public function priorityClaim(Request $request, string $groupId): JsonResponse
    {
        return $this->execute(function () use ($request, $groupId): array {
            $auth = $this->authContext($request);
            $this->engine->submitPriorityClaim(
                (string) $auth['user']['id'],
                $groupId,
                (string) $request->input('reason', ''),
                $request->input('customReason')
            );
            return ['ok' => true];
        }, 201);
    }

    public function approve(Request $request, string $payoutId): JsonResponse
    {
        return $this->execute(function () use ($request, $payoutId): JsonResponse|array {
            $auth = $this->authContext($request);
            $result = $this->engine->approvePayout((string) $auth['user']['id'], $payoutId, [
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
            return $result['payout'] ?? $result;
        });
    }

    public function reviewReason(Request $request, string $payoutId): JsonResponse
    {
        return $this->execute(function () use ($request, $payoutId): array {
            $auth = $this->authContext($request);
            return $this->engine->reviewPayoutReason((string) $auth['user']['id'], $payoutId, [
                'decision' => (string) $request->input('decision', 'approve'),
                'reason' => $request->input('reason'),
                'customReason' => $request->input('customReason'),
                'note' => $request->input('note'),
            ]);
        });
    }

    public function confirmRecipient(Request $request, string $payoutId): JsonResponse
    {
        return $this->execute(function () use ($request, $payoutId): JsonResponse|array {
            $auth = $this->authContext($request);
            $result = $this->engine->confirmPayoutRecipient((string) $auth['user']['id'], $payoutId, [
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
            return $result['payout'] ?? $result;
        });
    }

    public function release(Request $request, string $payoutId): JsonResponse
    {
        return $this->execute(function () use ($request, $payoutId): JsonResponse|array {
            $auth = $this->authContext($request);
            $result = $this->engine->releasePayout((string) $auth['user']['id'], $payoutId, [
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
            return $result['payout'] ?? $result;
        });
    }
}
