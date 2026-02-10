<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Services\Domain\DomainEngineService;
use App\Support\Domain\Exceptions\DomainHttpException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Throwable;

abstract class ApiController extends Controller
{
    public function __construct(
        protected readonly DomainEngineService $engine
    ) {
    }

    /**
     * @param callable():mixed $callback
     */
    protected function execute(callable $callback, int $successStatus = 200): JsonResponse
    {
        try {
            $data = $callback();
            if ($data instanceof JsonResponse) {
                return $data;
            }
            if ($successStatus === 204) {
                return response()->json(null, 204);
            }
            return response()->json(['data' => $data], $successStatus);
        } catch (DomainHttpException $exception) {
            return response()->json([
                'error' => [
                    'code' => $exception->errorCode(),
                    'message' => $exception->getMessage(),
                    'details' => $exception->details(),
                ],
            ], $exception->status());
        } catch (Throwable $exception) {
            return response()->json([
                'error' => [
                    'code' => 'INTERNAL_SERVER_ERROR',
                    'message' => $exception->getMessage(),
                ],
            ], 500);
        }
    }

    /**
     * @return array{user:array<string,mixed>,token:string}
     */
    protected function authContext(Request $request): array
    {
        $authorization = (string) $request->header('Authorization', '');
        $token = str_starts_with($authorization, 'Bearer ')
            ? substr($authorization, 7)
            : '';
        if ($token === '') {
            throw new DomainHttpException(401, 'UNAUTHORIZED', 'Missing Bearer token.');
        }
        $user = $this->engine->authenticate($token);
        return ['user' => $user, 'token' => $token];
    }

    /**
     * @param array<string,mixed> $user
     * @param array<int,string> $roles
     */
    protected function requireRole(array $user, array $roles): void
    {
        if (!in_array((string) $user['role'], $roles, true)) {
            throw new DomainHttpException(403, 'FORBIDDEN', 'Role-based access denied.');
        }
    }
}
