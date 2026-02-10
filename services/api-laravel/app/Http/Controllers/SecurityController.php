<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

final class SecurityController extends ApiController
{
    public function submitKyc(Request $request): JsonResponse
    {
        return $this->execute(fn () => $this->engine->submitKyc(
            (string) $this->authContext($request)['user']['id'],
            [
                'idType' => (string) $request->input('idType', ''),
                'idNumber' => (string) $request->input('idNumber', ''),
                'dob' => (string) $request->input('dob', ''),
                'selfieToken' => (string) $request->input('selfieToken', ''),
                'address' => $request->input('address'),
            ]
        ), 201);
    }

    public function createKycSession(Request $request): JsonResponse
    {
        return $this->execute(fn () => $this->engine->createKycSession((string) $this->authContext($request)['user']['id']), 201);
    }

    public function updateSecurity(Request $request): JsonResponse
    {
        return $this->execute(function () use ($request): JsonResponse|array {
            $auth = $this->authContext($request);
            $result = $this->engine->updateSecurity(
                (string) $auth['user']['id'],
                [
                    'mfaEnabled' => (bool) $request->input('mfaEnabled', true),
                    'biometricEnabled' => (bool) $request->input('biometricEnabled', false),
                ],
                $request->input('mfaChallengeId'),
                $request->input('mfaCode')
            );
            if (($result['mfaRequired'] ?? false) === true) {
                return response()->json([
                    'error' => [
                        'code' => 'MFA_REQUIRED',
                        'message' => 'MFA verification is required.',
                    ],
                    'data' => $result['challenge'] ?? null,
                ], 428);
            }
            return $result['user'] ?? $result;
        });
    }

    public function addPaymentMethod(Request $request): JsonResponse
    {
        return $this->execute(function () use ($request): JsonResponse|array {
            $auth = $this->authContext($request);
            $result = $this->engine->addPaymentMethod(
                (string) $auth['user']['id'],
                [
                    'type' => (string) $request->input('type', 'bank'),
                    'label' => (string) $request->input('label', ''),
                    'identifierTail' => (string) $request->input('identifierTail', ''),
                    'providerToken' => (string) $request->input('providerToken', ''),
                    'autoDebit' => (bool) $request->input('autoDebit', false),
                ],
                $request->input('mfaChallengeId'),
                $request->input('mfaCode')
            );
            if (($result['mfaRequired'] ?? false) === true) {
                return response()->json([
                    'error' => [
                        'code' => 'MFA_REQUIRED',
                        'message' => 'MFA verification is required.',
                    ],
                    'data' => $result['challenge'] ?? null,
                ], 428);
            }
            return $result['paymentMethod'] ?? $result;
        }, 201);
    }

    public function removePaymentMethod(Request $request, string $methodId): JsonResponse
    {
        return $this->execute(function () use ($request, $methodId): JsonResponse|array|null {
            $auth = $this->authContext($request);
            $result = $this->engine->removePaymentMethod(
                (string) $auth['user']['id'],
                $methodId,
                $request->input('mfaChallengeId'),
                $request->input('mfaCode')
            );
            if (($result['mfaRequired'] ?? false) === true) {
                return response()->json([
                    'error' => [
                        'code' => 'MFA_REQUIRED',
                        'message' => 'MFA verification is required.',
                    ],
                    'data' => $result['challenge'] ?? null,
                ], 428);
            }
            return null;
        }, 204);
    }

    public function removeDevice(Request $request, string $deviceId): JsonResponse
    {
        return $this->execute(function () use ($request, $deviceId): null {
            $auth = $this->authContext($request);
            $this->engine->removeDevice((string) $auth['user']['id'], $deviceId);
            return null;
        }, 204);
    }
}
