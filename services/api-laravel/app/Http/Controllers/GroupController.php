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
                'contributionAmount' => $request->query('contributionAmount'),
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
                'payoutFrequency' => (string) $request->input('payoutFrequency', 'monthly'),
                'payoutOrderLogic' => (string) $request->input('payoutOrderLogic', 'fixed'),
                'gracePeriodDays' => (int) $request->input('gracePeriodDays', 0),
                'requiresLeaderApproval' => (bool) $request->input('requiresLeaderApproval', true),
                'rules' => (string) $request->input('rules', ''),
            ]);
        }, 201);
    }

    public function joinByInvite(Request $request): JsonResponse
    {
        return $this->execute(function () use ($request): array {
            $auth = $this->authContext($request);
            return $this->engine->joinGroupByInvite(
                (string) $auth['user']['id'],
                (string) $request->input('inviteCode', '')
            );
        });
    }

    public function join(Request $request, string $groupId): JsonResponse
    {
        return $this->execute(function () use ($request, $groupId): array {
            $auth = $this->authContext($request);
            return $this->engine->joinGroup((string) $auth['user']['id'], $groupId);
        });
    }

    public function inviteLink(Request $request, string $groupId): JsonResponse
    {
        return $this->execute(function () use ($request, $groupId): array {
            $auth = $this->authContext($request);
            return $this->engine->groupInviteLink((string) $auth['user']['id'], $groupId);
        });
    }

    public function trustIndicators(Request $request, string $groupId): JsonResponse
    {
        return $this->execute(function () use ($request, $groupId): array {
            $auth = $this->authContext($request);
            return $this->engine->groupTrustIndicators((string) $auth['user']['id'], $groupId);
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

    public function updateConfig(Request $request, string $groupId): JsonResponse
    {
        return $this->execute(function () use ($request, $groupId): array {
            $auth = $this->authContext($request);
            $input = array_filter([
                'contributionAmount' => $request->input('contributionAmount'),
                'gracePeriodDays' => $request->input('gracePeriodDays'),
                'rules' => $request->input('rules'),
                'requiresLeaderApproval' => $request->input('requiresLeaderApproval'),
                'payoutOrderLogic' => $request->input('payoutOrderLogic'),
                'totalMembers' => $request->input('totalMembers'),
            ], static fn ($value): bool => $value !== null);
            return $this->engine->updateGroupConfig((string) $auth['user']['id'], $groupId, $input);
        });
    }

    public function updatePayoutOrder(Request $request, string $groupId): JsonResponse
    {
        return $this->execute(function () use ($request, $groupId): array {
            $auth = $this->authContext($request);
            $payoutOrder = $request->input('payoutOrder', []);
            return $this->engine->updatePayoutOrder(
                (string) $auth['user']['id'],
                $groupId,
                is_array($payoutOrder) ? array_map(static fn ($item): string => (string) $item, $payoutOrder) : []
            );
        });
    }

    public function moderateChat(Request $request, string $groupId): JsonResponse
    {
        return $this->execute(function () use ($request, $groupId): array {
            $auth = $this->authContext($request);
            return $this->engine->moderateGroupChat(
                (string) $auth['user']['id'],
                $groupId,
                (bool) $request->input('chatArchived', false)
            );
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
