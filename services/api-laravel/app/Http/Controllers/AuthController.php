<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

final class AuthController extends ApiController
{
    public function register(Request $request): JsonResponse
    {
        return $this->execute(fn (): array => $this->engine->register([
            'fullName' => (string) $request->input('fullName', ''),
            'email' => (string) $request->input('email', ''),
            'phone' => (string) $request->input('phone', ''),
            'password' => (string) $request->input('password', ''),
            'role' => (string) $request->input('role', 'member'),
            'acceptTerms' => (bool) $request->input('acceptTerms', false),
        ]), 201);
    }

    public function login(Request $request): JsonResponse
    {
        return $this->execute(function () use ($request): JsonResponse|array {
            $result = $this->engine->login([
                'email' => (string) $request->input('email', ''),
                'password' => (string) $request->input('password', ''),
                'deviceId' => (string) $request->input('deviceId', ''),
            ]);

            if (($result['requiresMfa'] ?? false) === true) {
                return response()->json([
                    'error' => [
                        'code' => 'MFA_REQUIRED',
                        'message' => 'MFA verification is required.',
                    ],
                    'data' => $result['challenge'] ?? null,
                ], 428);
            }

            return $result;
        });
    }

    public function verifyMfa(Request $request): JsonResponse
    {
        return $this->execute(fn (): array => $this->engine->verifyLoginMfa([
            'challengeId' => (string) $request->input('challengeId', ''),
            'code' => (string) $request->input('code', ''),
            'deviceId' => (string) $request->input('deviceId', ''),
        ]));
    }

    public function biometricLogin(Request $request): JsonResponse
    {
        return $this->execute(fn (): array => $this->engine->biometricLogin(
            (string) $request->input('email', ''),
            (string) $request->input('deviceId', '')
        ));
    }

    public function logout(Request $request): JsonResponse
    {
        return $this->execute(function () use ($request): null {
            $auth = $this->authContext($request);
            $this->engine->logout((string) $auth['user']['id'], $auth['token']);
            return null;
        }, 204);
    }

    public function me(Request $request): JsonResponse
    {
        return $this->execute(function () use ($request): array {
            $auth = $this->authContext($request);
            return $auth['user'];
        });
    }
}
