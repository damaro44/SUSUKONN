<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

final class GroupController extends ApiController
{
    public function index(Request $request): JsonResponse
    {
        return $this->execute(function () use ($request): array {
            $auth = $this->authContext($request);
            return $this->engine->listGroups((string) $auth['user']['id'], [
                'query' => $request->query('query'),
                'community' => $request->query('community'),
                'location' => $request->query('location'),
                'maxContribution' => $request->query('maxContribution'),
                'startDate' => $request->query('startDate'),
            ]);
        });
    }

    public function store(Request $request): JsonResponse
    {
        return $this->execute(function () use ($request): array {
            $auth = $this->authContext($request);
            return $this->engine->createGroup((string) $auth['user']['id'], [
                'name' => (string) $request->input('name', ''),
                'description' => (string) $request->input('description', ''),
                'communityType' => (string) $request->input('communityType', ''),
                'location' => (string) $request->input('location', ''),
                'startDate' => (string) $request->input('startDate', ''),
                'contributionAmount' => (float) $request->input('contributionAmount', 0),
                'currency' => (string) $request->input('currency', 'USD'),
                'totalMembers' => (int) $request->input('totalMembers', 2),
                'payoutOrderLogic' => (string) $request->input('payoutOrderLogic', 'fixed'),
                'gracePeriodDays' => (int) $request->input('gracePeriodDays', 0),
                'requiresLeaderApproval' => (bool) $request->input('requiresLeaderApproval', true),
                'rules' => (string) $request->input('rules', ''),
            ]);
        }, 201);
    }

    public function join(Request $request, string $groupId): JsonResponse
    {
        return $this->execute(function () use ($request, $groupId): array {
            $auth = $this->authContext($request);
            return $this->engine->joinGroup((string) $auth['user']['id'], $groupId);
        });
    }

    public function reviewJoinRequest(Request $request, string $groupId, string $userId): JsonResponse
    {
        return $this->execute(function () use ($request, $groupId, $userId): array {
            $auth = $this->authContext($request);
            return $this->engine->reviewJoinRequest(
                (string) $auth['user']['id'],
                $groupId,
                $userId,
                (string) $request->input('decision', 'reject')
            );
        });
    }

    public function sendReminders(Request $request, string $groupId): JsonResponse
    {
        return $this->execute(function () use ($request, $groupId): array {
            $auth = $this->authContext($request);
            return $this->engine->sendGroupReminders((string) $auth['user']['id'], $groupId);
        });
    }

    public function updateStatus(Request $request, string $groupId): JsonResponse
    {
        return $this->execute(function () use ($request, $groupId): array {
            $auth = $this->authContext($request);
            $this->requireRole($auth['user'], ['admin']);
            return $this->engine->updateGroupStatus(
                (string) $auth['user']['id'],
                $groupId,
                (string) $request->input('status', '')
            );
        });
    }
}
