<?php

declare(strict_types=1);

namespace App\Services\Domain;

use App\Services\Providers\KycProviderInterface;
use App\Services\Providers\KycProviderManager;
use App\Services\Providers\PaymentGatewayInterface;
use App\Services\Providers\PaymentGatewayManager;
use App\Support\Domain\Constants;
use App\Support\Domain\Helpers;

final class DomainEngineService
{
    /** @var array<string,mixed> */
    private array $state;

    public function __construct(
        private readonly DomainStateRepository $repository,
        private readonly ?PaymentGatewayInterface $paymentGateway = null,
        private readonly ?KycProviderInterface $kycProvider = null
    ) {
        $this->state = $this->repository->get();
        $this->reconcile();
        $this->persist();
    }

    public function resetStateForTests(): void
    {
        $this->repository->reset();
        $this->state = $this->repository->get();
        $this->reconcile();
        $this->persist();
    }

    /**
     * @return array<string,mixed>
     */
    public function stateSnapshot(): array
    {
        return json_decode(json_encode($this->state, JSON_THROW_ON_ERROR), true, 512, JSON_THROW_ON_ERROR);
    }

    /**
     * @param array<string,mixed> $input
     * @return array<string,mixed>
     */
    public function register(array $input): array
    {
        $fullName = trim((string) ($input['fullName'] ?? ''));
        $email = Helpers::normalizeEmail((string) ($input['email'] ?? ''));
        $phone = Helpers::normalizePhone((string) ($input['phone'] ?? ''));
        $password = (string) ($input['password'] ?? '');
        $role = (string) ($input['role'] ?? 'member');
        $acceptTerms = (bool) ($input['acceptTerms'] ?? false);

        Helpers::assert($acceptTerms, 400, 'TERMS_REQUIRED', 'Terms must be accepted.');
        Helpers::assert($fullName !== '', 400, 'INVALID_INPUT', 'Full name is required.');
        Helpers::assert($email !== '', 400, 'INVALID_INPUT', 'Email is required.');
        Helpers::assert($phone !== '', 400, 'INVALID_INPUT', 'Phone is required.');
        Helpers::assert(
            strlen($password) >= 8 && preg_match('/[A-Za-z]/', $password) === 1 && preg_match('/\d/', $password) === 1,
            400,
            'WEAK_PASSWORD',
            'Password must include letters and numbers and be at least 8 characters.'
        );
        Helpers::assert(
            $this->firstWhere($this->state['users'], static fn (array $user): bool => $user['email'] === $email) === null,
            409,
            'EMAIL_EXISTS',
            'Email already exists.'
        );
        Helpers::assert(
            $this->firstWhere($this->state['users'], static fn (array $user): bool => $user['phone'] === $phone) === null,
            409,
            'PHONE_EXISTS',
            'Phone already exists.'
        );

        $normalizedRole = in_array($role, ['member', 'leader'], true) ? $role : 'member';
        $salt = Helpers::uid('salt');
        $user = [
            'id' => Helpers::uid('usr'),
            'fullName' => $fullName,
            'email' => $email,
            'phone' => $phone,
            'role' => $normalizedRole,
            'passwordHash' => Helpers::hashPassword($password, $salt),
            'salt' => $salt,
            'acceptedTerms' => true,
            'verifiedBadge' => false,
            'biometricEnabled' => false,
            'mfaEnabled' => true,
            'status' => 'active',
            'knownDevices' => [],
            'paymentMethods' => [],
            'metrics' => [
                'paidContributions' => 0,
                'completedGroups' => 0,
                'internalTrustScore' => 50,
            ],
            'kyc' => [
                'status' => 'unverified',
                'idType' => '',
                'idNumberToken' => '',
                'dob' => '',
                'selfieToken' => '',
            ],
            'createdAt' => Helpers::nowIso(),
        ];
        $this->state['users'][] = $user;
        $this->notify($user['id'], 'Welcome to SusuKonnect', 'Complete KYC verification before joining groups and receiving payouts.', 'onboarding', 'welcome-' . $user['id']);
        $this->logAudit($user['id'], 'REGISTER_ACCOUNT', 'user', $user['id'], []);
        $this->persist();

        return [
            'id' => $user['id'],
            'email' => $user['email'],
            'role' => $user['role'],
            'fullName' => $user['fullName'],
        ];
    }

    /**
     * @param array{email:string,password:string,deviceId:string} $input
     * @return array<string,mixed>
     */
    public function login(array $input): array
    {
        $email = Helpers::normalizeEmail($input['email']);
        $password = (string) $input['password'];
        $deviceId = (string) $input['deviceId'];
        $user = $this->findUserByEmail($email);
        Helpers::assert($user !== null, 401, 'INVALID_CREDENTIALS', 'Invalid credentials.');
        Helpers::assert($user['status'] === 'active', 403, 'USER_SUSPENDED', 'User account is suspended.');

        $attempts = $this->state['authControls']['loginAttempts'][$email] ?? ['count' => 0];
        if (isset($attempts['lockedUntil']) && strtotime((string) $attempts['lockedUntil']) > time()) {
            throw new \App\Support\Domain\Exceptions\DomainHttpException(429, 'ACCOUNT_LOCKED', 'Too many failed attempts. Try later.');
        }

        $expectedHash = Helpers::hashPassword($password, (string) $user['salt']);
        if ($expectedHash !== $user['passwordHash']) {
            $attempts['count'] = ((int) ($attempts['count'] ?? 0)) + 1;
            if ($attempts['count'] >= 5) {
                $attempts['count'] = 0;
                $attempts['lockedUntil'] = Helpers::addMinutes(Helpers::nowIso(), 15);
            }
            $this->state['authControls']['loginAttempts'][$email] = $attempts;
            $this->persist();
            throw new \App\Support\Domain\Exceptions\DomainHttpException(401, 'INVALID_CREDENTIALS', 'Invalid credentials.');
        }
        $this->state['authControls']['loginAttempts'][$email] = ['count' => 0];

        $knownDevice = $this->firstWhere($user['knownDevices'], static fn (array $device): bool => $device['id'] === $deviceId);
        if ($knownDevice === null || $user['mfaEnabled']) {
            $challenge = $this->createMfaChallenge((string) $user['id'], 'login');
            $this->persist();
            return [
                'requiresMfa' => true,
                'challenge' => $challenge,
            ];
        }

        $this->touchDevice((string) $user['id'], $deviceId, 'Trusted device');
        $tokens = $this->issueSession((string) $user['id'], $deviceId);
        $this->logAudit((string) $user['id'], 'LOGIN_SUCCESS', 'user', (string) $user['id'], ['deviceId' => $deviceId]);
        $this->persist();

        return [
            'requiresMfa' => false,
            'tokens' => $tokens,
            'user' => $this->publicUser((string) $user['id']),
        ];
    }

    /**
     * @param array{challengeId:string,code:string,deviceId:string} $input
     * @return array<string,mixed>
     */
    public function verifyLoginMfa(array $input): array
    {
        $challenge = $this->verifyMfaChallenge($input['challengeId'], $input['code'], 'login');
        $userId = (string) $challenge['userId'];
        $this->touchDevice($userId, (string) $input['deviceId'], 'Trusted device');
        $tokens = $this->issueSession($userId, (string) $input['deviceId']);
        $this->logAudit($userId, 'LOGIN_MFA_VERIFIED', 'user', $userId, ['deviceId' => $input['deviceId']]);
        $this->persist();

        return [
            'tokens' => $tokens,
            'user' => $this->publicUser($userId),
        ];
    }

    /**
     * @return array<string,mixed>
     */
    public function biometricLogin(string $emailRaw, string $deviceId): array
    {
        $email = Helpers::normalizeEmail($emailRaw);
        $user = $this->findUserByEmail($email);
        Helpers::assert($user !== null, 404, 'NOT_FOUND', 'User not found.');
        Helpers::assert((bool) $user['biometricEnabled'], 400, 'BIOMETRIC_DISABLED', 'Biometric login not enabled.');
        Helpers::assert(
            $this->firstWhere($user['knownDevices'], static fn (array $device): bool => $device['id'] === $deviceId) !== null,
            401,
            'UNKNOWN_DEVICE',
            'Device is not trusted.'
        );

        $tokens = $this->issueSession((string) $user['id'], $deviceId);
        $this->logAudit((string) $user['id'], 'BIOMETRIC_LOGIN_SUCCESS', 'user', (string) $user['id'], ['deviceId' => $deviceId]);
        $this->persist();

        return [
            'tokens' => $tokens,
            'user' => $this->publicUser((string) $user['id']),
        ];
    }

    public function logout(string $userId, string $sessionToken): void
    {
        $sessions = array_values(array_filter(
            $this->state['sessions'],
            static fn (array $session): bool => !($session['userId'] === $userId && $session['token'] === $sessionToken)
        ));
        $this->state['sessions'] = $sessions;
        $this->logAudit($userId, 'LOGOUT', 'user', $userId, []);
        $this->persist();
    }

    /**
     * @return array<string,mixed>
     */
    public function authenticate(string $token): array
    {
        $session = $this->firstWhere($this->state['sessions'], static fn (array $candidate): bool => $candidate['token'] === $token);
        Helpers::assert($session !== null, 401, 'UNAUTHORIZED', 'Invalid token.');
        Helpers::assert(strtotime((string) $session['expiresAt']) > time(), 401, 'TOKEN_EXPIRED', 'Session expired.');
        return $this->publicUser((string) $session['userId']);
    }

    /**
     * @return array<string,mixed>
     */
    public function dashboard(string $userId): array
    {
        $groups = $this->groupsForUser($userId);
        $notifications = $this->userNotifications($userId);
        $pendingContributions = array_values(array_filter($this->state['contributions'], function (array $entry) use ($userId): bool {
            if ($entry['userId'] !== $userId) {
                return false;
            }
            if (!in_array($entry['status'], ['pending', 'late'], true)) {
                return false;
            }
            $group = $this->groupById((string) $entry['groupId']);
            return $group !== null && $group['cycle'] === $entry['cycle'];
        }));
        $receivedPayouts = array_values(array_filter($this->state['payouts'], static fn (array $payout): bool => $payout['recipientId'] === $userId && $payout['status'] === 'released'));

        $recentAudit = array_values(array_reverse(array_slice(array_values(array_filter(
            $this->state['auditLogs'],
            static fn (array $log): bool => $log['actorId'] === $userId || (($log['metadata']['targetUserId'] ?? null) === $userId)
        )), -10)));

        return [
            'summary' => [
                'activeGroups' => count(array_filter($groups, static fn (array $group): bool => $group['status'] === 'active')),
                'pendingContributions' => count($pendingContributions),
                'receivedPayouts' => count($receivedPayouts),
                'unreadNotifications' => count(array_filter($notifications, static fn (array $note): bool => !$note['read'])),
            ],
            'upcomingEvents' => array_slice($this->calendarEvents($userId), 0, 10),
            'recentAudit' => $recentAudit,
            'user' => $this->publicUser($userId),
        ];
    }

    /**
     * @param array<string,string|null> $filters
     * @return array<int,array<string,mixed>>
     */
    public function listGroups(string $userId, array $filters = []): array
    {
        unset($userId);
        $query = strtolower((string) ($filters['query'] ?? ''));
        $community = strtolower((string) ($filters['community'] ?? ''));
        $location = strtolower((string) ($filters['location'] ?? ''));
        $maxContribution = (float) ($filters['maxContribution'] ?? 0);
        $startDate = (string) ($filters['startDate'] ?? '');

        return array_values(array_filter($this->state['groups'], static function (array $group) use ($query, $community, $location, $maxContribution, $startDate): bool {
            if ($query !== '' && !str_contains(strtolower((string) $group['name']), $query)) {
                return false;
            }
            if ($community !== '' && !str_contains(strtolower((string) $group['communityType']), $community)) {
                return false;
            }
            if ($location !== '' && !str_contains(strtolower((string) $group['location']), $location)) {
                return false;
            }
            if ($maxContribution > 0 && (float) $group['contributionAmount'] > $maxContribution) {
                return false;
            }
            if ($startDate !== '' && strtotime((string) $group['startDate']) < strtotime($startDate)) {
                return false;
            }
            return true;
        }));
    }

    /**
     * @param array<string,mixed> $input
     * @return array<string,mixed>
     */
    public function createGroup(string $userId, array $input): array
    {
        $actor = $this->requireUser($userId);
        Helpers::assert(($actor['kyc']['status'] ?? 'unverified') === 'verified', 403, 'KYC_REQUIRED', 'KYC verification is required.');
        Helpers::assert(((int) $input['totalMembers']) >= 2, 400, 'INVALID_GROUP_SIZE', 'Group requires at least 2 members.');
        Helpers::assert(in_array((string) $input['currency'], Constants::CURRENCIES, true), 400, 'INVALID_CURRENCY', 'Unsupported currency.');

        if ($actor['role'] === 'member') {
            $this->mutateUser($userId, static function (array &$user): void {
                $user['role'] = 'leader';
            });
        }

        $group = [
            'id' => Helpers::uid('grp'),
            'inviteCode' => Helpers::uid('join'),
            'name' => trim((string) ($input['name'] ?? '')),
            'description' => trim((string) ($input['description'] ?? '')),
            'communityType' => trim((string) ($input['communityType'] ?? '')),
            'location' => trim((string) ($input['location'] ?? '')),
            'startDate' => (string) $input['startDate'],
            'contributionAmount' => (float) $input['contributionAmount'],
            'currency' => (string) $input['currency'],
            'totalMembers' => (int) $input['totalMembers'],
            'payoutFrequency' => 'monthly',
            'payoutOrderLogic' => (string) $input['payoutOrderLogic'],
            'gracePeriodDays' => (int) $input['gracePeriodDays'],
            'requiresLeaderApproval' => (bool) $input['requiresLeaderApproval'],
            'rules' => trim((string) ($input['rules'] ?? '')),
            'leaderId' => $userId,
            'memberIds' => [$userId],
            'joinRequests' => [],
            'payoutOrder' => [$userId],
            'cycle' => 1,
            'status' => 'active',
            'chatArchived' => false,
            'createdAt' => Helpers::nowIso(),
        ];
        $this->state['groups'][] = $group;
        $this->ensureCycleContributions($group);
        $this->logAudit($userId, 'CREATE_GROUP', 'group', $group['id'], [
            'amount' => $group['contributionAmount'],
            'currency' => $group['currency'],
        ]);
        $this->reconcile();
        $this->persist();

        return $group;
    }

    /**
     * @return array<string,mixed>
     */
    public function joinGroup(string $userId, string $groupId): array
    {
        $user = $this->requireUser($userId);
        $group = $this->requireGroup($groupId);
        Helpers::assert(($user['kyc']['status'] ?? 'unverified') === 'verified', 403, 'KYC_REQUIRED', 'KYC must be verified to join groups.');
        Helpers::assert($group['status'] === 'active', 409, 'GROUP_NOT_ACTIVE', 'Group is not active.');
        Helpers::assert(!in_array($userId, $group['memberIds'], true), 409, 'ALREADY_MEMBER', 'Already in group.');
        Helpers::assert(count($group['memberIds']) < (int) $group['totalMembers'], 409, 'GROUP_FULL', 'Group is full.');

        if ($group['requiresLeaderApproval']) {
            $this->mutateGroup($groupId, static function (array &$mutable) use ($userId): void {
                if (!in_array($userId, $mutable['joinRequests'], true)) {
                    $mutable['joinRequests'][] = $userId;
                }
            });
            $this->notify((string) $group['leaderId'], 'Join request pending', $user['fullName'] . ' requested to join ' . $group['name'] . '.', 'group', 'join-request-' . $groupId . '-' . $userId);
            $this->logAudit($userId, 'REQUEST_JOIN_GROUP', 'group', $groupId, ['targetUserId' => $userId]);
            $this->persist();
            return $this->requireGroup($groupId);
        }

        $this->addMemberToGroup($groupId, $userId);
        $this->logAudit($userId, 'JOIN_GROUP', 'group', $groupId, ['targetUserId' => $userId]);
        $this->reconcile();
        $this->persist();
        return $this->requireGroup($groupId);
    }

    /**
     * @return array<string,mixed>
     */
    public function reviewJoinRequest(string $actorId, string $groupId, string $targetUserId, string $decision): array
    {
        $actor = $this->requireUser($actorId);
        $group = $this->requireGroup($groupId);
        $this->assertGroupManager($actor, $group);
        Helpers::assert(in_array($targetUserId, $group['joinRequests'], true), 404, 'REQUEST_NOT_FOUND', 'No pending request.');

        $this->mutateGroup($groupId, static function (array &$mutable) use ($targetUserId): void {
            $mutable['joinRequests'] = array_values(array_filter(
                $mutable['joinRequests'],
                static fn (string $candidate): bool => $candidate !== $targetUserId
            ));
        });

        if ($decision === 'approve') {
            $this->addMemberToGroup($groupId, $targetUserId);
            $this->notify($targetUserId, 'Join request approved', 'You were added to ' . $group['name'] . '.', 'group', 'join-approved-' . $groupId . '-' . $targetUserId);
            $this->logAudit($actorId, 'APPROVE_JOIN_REQUEST', 'group', $groupId, ['targetUserId' => $targetUserId]);
        } else {
            $this->notify($targetUserId, 'Join request rejected', 'Your request for ' . $group['name'] . ' was declined.', 'group', 'join-rejected-' . $groupId . '-' . $targetUserId);
            $this->logAudit($actorId, 'REJECT_JOIN_REQUEST', 'group', $groupId, ['targetUserId' => $targetUserId]);
        }
        $this->reconcile();
        $this->persist();
        return $this->requireGroup($groupId);
    }

    /**
     * @return array{reminded:int}
     */
    public function sendGroupReminders(string $actorId, string $groupId): array
    {
        $actor = $this->requireUser($actorId);
        $group = $this->requireGroup($groupId);
        $this->assertGroupManager($actor, $group);
        $pending = array_values(array_filter(
            $this->cycleContributions($groupId, (int) $group['cycle']),
            static fn (array $entry): bool => in_array($entry['status'], ['pending', 'late'], true)
        ));
        foreach ($pending as $entry) {
            $this->notify((string) $entry['userId'], 'Contribution reminder', 'Your contribution is due for ' . $group['name'] . '.', 'reminder', 'manual-reminder-' . $groupId . '-' . $group['cycle'] . '-' . $entry['userId'] . '-' . date('Y-m-d'));
        }
        $this->logAudit($actorId, 'SEND_GROUP_REMINDER', 'group', $groupId, ['pendingCount' => count($pending)]);
        $this->persist();
        return ['reminded' => count($pending)];
    }

    /**
     * @return array<int,array<string,mixed>>
     */
    public function listContributions(string $userId, ?string $groupId = null): array
    {
        $groupIds = array_map(static fn (array $group): string => (string) $group['id'], $this->groupsForUser($userId));
        return array_values(array_filter($this->state['contributions'], static function (array $entry) use ($groupIds, $groupId): bool {
            if (!in_array((string) $entry['groupId'], $groupIds, true)) {
                return false;
            }
            if ($groupId !== null && $groupId !== '' && $entry['groupId'] !== $groupId) {
                return false;
            }
            return true;
        }));
    }

    /**
     * @param array<string,mixed> $payload
     * @return array<string,mixed>
     */
    public function payContribution(string $userId, string $contributionId, array $payload): array
    {
        $user = $this->requireUser($userId);
        $contribution = $this->findContribution($contributionId);
        Helpers::assert($contribution !== null, 404, 'NOT_FOUND', 'Contribution not found.');
        Helpers::assert($contribution['userId'] === $userId, 403, 'FORBIDDEN', 'Cannot pay another user contribution.');
        Helpers::assert($contribution['status'] !== 'paid', 409, 'ALREADY_PAID', 'Contribution already paid.');
        $group = $this->requireGroup((string) $contribution['groupId']);
        Helpers::assert($group['status'] === 'active', 409, 'GROUP_NOT_ACTIVE', 'Group is not active.');

        $methodId = (string) ($payload['methodId'] ?? '');
        $paymentMethod = $this->firstWhere($user['paymentMethods'], static fn (array $method): bool => $method['id'] === $methodId);
        Helpers::assert($paymentMethod !== null, 404, 'METHOD_NOT_FOUND', 'Payment method not found.');

        $mfaResult = $this->assertMfa($userId, 'contribution_pay', $payload['mfaChallengeId'] ?? null, $payload['mfaCode'] ?? null);
        if (!$mfaResult['verified']) {
            $this->persist();
            return ['mfaRequired' => true, 'challenge' => $mfaResult];
        }

        $provider = $this->paymentGateway()->chargeContribution([
            'amount' => (float) $contribution['amount'],
            'currency' => (string) $group['currency'],
            'paymentMethodType' => (string) $paymentMethod['type'],
            'paymentTokenRef' => (string) $paymentMethod['tokenRef'],
            'metadata' => [
                'userId' => $userId,
                'groupId' => (string) $group['id'],
                'contributionId' => (string) $contribution['id'],
            ],
        ]);
        Helpers::assert((bool) $provider['ok'], 422, 'PAYMENT_FAILED', 'Contribution payment failed.');

        $enableAutoDebit = (bool) ($payload['enableAutoDebit'] ?? false);
        $this->mutateContribution($contributionId, static function (array &$mutable) use ($methodId, $paymentMethod, $provider, $enableAutoDebit): void {
            $mutable['status'] = 'paid';
            $mutable['methodId'] = $methodId;
            $mutable['methodType'] = $paymentMethod['type'];
            $mutable['providerReference'] = $provider['reference'];
            $mutable['paidAt'] = Helpers::nowIso();
            $mutable['autoDebit'] = $enableAutoDebit;
        });
        if ($enableAutoDebit) {
            $this->mutateUser($userId, static function (array &$mutableUser) use ($methodId): void {
                foreach ($mutableUser['paymentMethods'] as &$method) {
                    if ($method['id'] === $methodId) {
                        $method['autoDebit'] = true;
                    }
                }
                unset($method);
            });
        }

        $this->notify((string) $group['leaderId'], 'Contribution paid', $user['fullName'] . ' paid contribution in ' . $group['name'] . '.', 'payment', 'contribution-paid-' . $contributionId);
        $this->logAudit($userId, 'PAY_CONTRIBUTION', 'contribution', $contributionId, [
            'groupId' => $group['id'],
            'providerReference' => $provider['reference'],
        ]);
        $this->reconcile();
        $this->persist();

        return [
            'mfaRequired' => false,
            'contribution' => $this->findContribution($contributionId),
        ];
    }

    /**
     * @return array<int,array<string,mixed>>
     */
    public function listPayouts(string $userId, ?string $groupId = null): array
    {
        $groupIds = array_map(static fn (array $group): string => (string) $group['id'], $this->groupsForUser($userId));
        return array_values(array_filter($this->state['payouts'], static function (array $payout) use ($groupIds, $groupId): bool {
            if (!in_array((string) $payout['groupId'], $groupIds, true)) {
                return false;
            }
            if ($groupId !== null && $groupId !== '' && $payout['groupId'] !== $groupId) {
                return false;
            }
            return true;
        }));
    }

    /**
     * @return array<string,mixed>
     */
    public function requestPayout(string $userId, string $groupId, string $reason, ?string $customReason = null): array
    {
        $group = $this->requireGroup($groupId);
        Helpers::assert(in_array($userId, $group['memberIds'], true), 403, 'FORBIDDEN', 'Only members can request payout.');
        Helpers::assert(in_array($reason, Constants::PAYOUT_REASONS, true), 400, 'INVALID_REASON', 'Unsupported reason.');
        Helpers::assert($this->allContributionsPaid($groupId, (int) $group['cycle']), 409, 'CONTRIBUTIONS_PENDING', 'Contributions pending.');
        Helpers::assert($this->currentPayout($groupId, (int) $group['cycle']) === null, 409, 'PAYOUT_EXISTS', 'Payout already requested.');
        $recipientId = $this->eligibleRecipient($group, (int) $group['cycle']);
        Helpers::assert($recipientId === $userId, 403, 'NOT_ELIGIBLE', 'You are not eligible this cycle.');

        $recipient = $this->requireUser($userId);
        Helpers::assert(($recipient['kyc']['status'] ?? 'unverified') === 'verified', 403, 'KYC_REQUIRED', 'KYC required for payouts.');
        $amount = array_reduce(
            $this->cycleContributions($groupId, (int) $group['cycle']),
            static fn (float $sum, array $entry): float => $sum + (float) $entry['amount'],
            0.0
        );

        $payout = [
            'id' => Helpers::uid('pay'),
            'groupId' => $groupId,
            'cycle' => (int) $group['cycle'],
            'recipientId' => $userId,
            'amount' => $amount,
            'currency' => $group['currency'],
            'reason' => $reason,
            'customReason' => $customReason,
            'status' => 'requested',
            'requestedAt' => Helpers::nowIso(),
            'recipientMfaConfirmed' => false,
            'platformFee' => 0.0,
            'netAmount' => 0.0,
        ];
        $this->state['payouts'][] = $payout;
        $this->notify((string) $group['leaderId'], 'Payout request submitted', $recipient['fullName'] . ' requested payout in ' . $group['name'] . '.', 'payout', 'payout-request-' . $payout['id']);
        foreach ($this->adminUsers() as $admin) {
            $this->notify((string) $admin['id'], 'Payout review required', 'Payout request in ' . $group['name'] . ' needs review.', 'compliance', 'payout-review-' . $payout['id'] . '-' . $admin['id']);
        }
        $this->logAudit($userId, 'REQUEST_PAYOUT', 'payout', $payout['id'], ['groupId' => $groupId]);
        $this->persist();
        return $payout;
    }

    public function submitVote(string $userId, string $groupId, string $candidateId, ?string $note = null): void
    {
        $group = $this->requireGroup($groupId);
        Helpers::assert(in_array($userId, $group['memberIds'], true), 403, 'FORBIDDEN', 'Only members can vote.');
        Helpers::assert(in_array($candidateId, $group['memberIds'], true), 400, 'INVALID_CANDIDATE', 'Candidate not in group.');
        Helpers::assert($group['payoutOrderLogic'] === 'voting', 400, 'INVALID_LOGIC', 'Group is not voting-based.');
        $existing = $this->firstWhere($this->state['payoutVotes'], static fn (array $vote): bool => $vote['groupId'] === $groupId && $vote['cycle'] === $group['cycle'] && $vote['voterId'] === $userId);
        Helpers::assert($existing === null, 409, 'ALREADY_VOTED', 'Already voted this cycle.');
        $this->state['payoutVotes'][] = [
            'id' => Helpers::uid('vote'),
            'groupId' => $groupId,
            'cycle' => $group['cycle'],
            'voterId' => $userId,
            'candidateId' => $candidateId,
            'note' => $note,
            'createdAt' => Helpers::nowIso(),
        ];
        $this->logAudit($userId, 'SUBMIT_PAYOUT_VOTE', 'group', $groupId, ['targetUserId' => $candidateId]);
        $this->persist();
    }

    public function submitPriorityClaim(string $userId, string $groupId, string $reason, ?string $customReason = null): void
    {
        $group = $this->requireGroup($groupId);
        Helpers::assert(in_array($userId, $group['memberIds'], true), 403, 'FORBIDDEN', 'Only members can submit claim.');
        Helpers::assert($group['payoutOrderLogic'] === 'priority', 400, 'INVALID_LOGIC', 'Group is not priority-based.');
        Helpers::assert(in_array($reason, Constants::PAYOUT_REASONS, true), 400, 'INVALID_REASON', 'Unsupported reason.');
        $existing = $this->firstWhere($this->state['priorityClaims'], static fn (array $claim): bool => $claim['groupId'] === $groupId && $claim['cycle'] === $group['cycle'] && $claim['userId'] === $userId);
        Helpers::assert($existing === null, 409, 'ALREADY_SUBMITTED', 'Already submitted claim this cycle.');
        $this->state['priorityClaims'][] = [
            'id' => Helpers::uid('claim'),
            'groupId' => $groupId,
            'cycle' => $group['cycle'],
            'userId' => $userId,
            'reason' => $reason,
            'customReason' => $customReason,
            'weight' => Constants::PRIORITY_WEIGHTS[$reason] ?? Constants::PRIORITY_WEIGHTS['Custom reason'],
            'createdAt' => Helpers::nowIso(),
        ];
        $this->logAudit($userId, 'SUBMIT_PRIORITY_CLAIM', 'group', $groupId, ['reason' => $reason]);
        $this->persist();
    }

    /**
     * @param array<string,mixed> $payload
     * @return array<string,mixed>
     */
    public function approvePayout(string $actorId, string $payoutId, array $payload): array
    {
        $actor = $this->requireUser($actorId);
        $payout = $this->requirePayout($payoutId);
        $group = $this->requireGroup((string) $payout['groupId']);
        Helpers::assert($actor['role'] === 'admin' || $group['leaderId'] === $actorId, 403, 'FORBIDDEN', 'Only admin or group leader can approve payout.');

        $mfaResult = $this->assertMfa($actorId, 'payout_approve', $payload['mfaChallengeId'] ?? null, $payload['mfaCode'] ?? null);
        if (!$mfaResult['verified']) {
            $this->persist();
            return ['mfaRequired' => true, 'challenge' => $mfaResult];
        }

        $this->mutatePayout($payoutId, function (array &$mutable) use ($actor): void {
            if ($actor['role'] === 'admin') {
                $mutable['adminApprovedBy'] = $actor['id'];
            } else {
                $mutable['leaderApprovedBy'] = $actor['id'];
            }
        });
        $updated = $this->requirePayout($payoutId);
        $this->refreshPayoutStatus($group, $updated);
        $this->mutatePayout($payoutId, static function (array &$mutable) use ($updated): void {
            $mutable = $updated;
        });
        $this->logAudit($actorId, 'APPROVE_PAYOUT', 'payout', $payoutId, []);
        $this->persist();
        return ['mfaRequired' => false, 'payout' => $updated];
    }

    /**
     * @param array<string,mixed> $payload
     * @return array<string,mixed>
     */
    public function confirmPayoutRecipient(string $userId, string $payoutId, array $payload): array
    {
        $payout = $this->requirePayout($payoutId);
        Helpers::assert($payout['recipientId'] === $userId, 403, 'FORBIDDEN', 'Only recipient can confirm.');
        $mfaResult = $this->assertMfa($userId, 'payout_approve', $payload['mfaChallengeId'] ?? null, $payload['mfaCode'] ?? null);
        if (!$mfaResult['verified']) {
            $this->persist();
            return ['mfaRequired' => true, 'challenge' => $mfaResult];
        }
        $this->mutatePayout($payoutId, static function (array &$mutable): void {
            $mutable['recipientMfaConfirmed'] = true;
        });
        $this->logAudit($userId, 'CONFIRM_PAYOUT_MFA', 'payout', $payoutId, []);
        $this->persist();
        return ['mfaRequired' => false, 'payout' => $this->requirePayout($payoutId)];
    }

    /**
     * @param array<string,mixed> $payload
     * @return array<string,mixed>
     */
    public function releasePayout(string $actorId, string $payoutId, array $payload): array
    {
        $actor = $this->requireUser($actorId);
        $payout = $this->requirePayout($payoutId);
        $group = $this->requireGroup((string) $payout['groupId']);
        Helpers::assert($actor['role'] === 'admin' || $group['leaderId'] === $actorId, 403, 'FORBIDDEN', 'Only manager can release payout.');
        Helpers::assert($this->allContributionsPaid((string) $group['id'], (int) $group['cycle']), 409, 'CONTRIBUTIONS_PENDING', 'Contributions pending.');
        $this->refreshPayoutStatus($group, $payout);
        Helpers::assert($payout['status'] === 'approved', 409, 'PAYOUT_NOT_APPROVED', 'Payout is not approved.');
        Helpers::assert((bool) $payout['recipientMfaConfirmed'], 409, 'RECIPIENT_MFA_PENDING', 'Recipient MFA pending.');

        $mfaResult = $this->assertMfa($actorId, 'payout_release', $payload['mfaChallengeId'] ?? null, $payload['mfaCode'] ?? null);
        if (!$mfaResult['verified']) {
            $this->persist();
            return ['mfaRequired' => true, 'challenge' => $mfaResult];
        }

        $recipient = $this->requireUser((string) $payout['recipientId']);
        $preferredMethod = $recipient['paymentMethods'][0] ?? null;
        $channel = ($preferredMethod['type'] ?? 'stripe') === 'paypal' ? 'paypal' : 'stripe';
        $destination = (string) ($preferredMethod['tokenRef'] ?? 'manual_destination');

        $feeRate = (float) ($this->state['meta']['platformFeeRate'] ?? 0.015);
        $fee = Helpers::roundTwo(((float) $payout['amount']) * $feeRate);
        $netAmount = Helpers::roundTwo(((float) $payout['amount']) - $fee);
        $provider = $this->paymentGateway()->releasePayout([
            'amount' => $netAmount,
            'currency' => (string) $payout['currency'],
            'payoutChannel' => $channel,
            'destinationTokenRef' => $destination,
            'recipientEmail' => (string) $recipient['email'],
            'metadata' => [
                'payoutId' => $payoutId,
                'groupId' => (string) $group['id'],
            ],
        ]);
        Helpers::assert((bool) $provider['ok'], 422, 'PAYOUT_RELEASE_FAILED', 'Provider payout release failed.');

        $this->mutatePayout($payoutId, static function (array &$mutable) use ($fee, $netAmount, $provider): void {
            $mutable['status'] = 'released';
            $mutable['platformFee'] = $fee;
            $mutable['netAmount'] = $netAmount;
            $mutable['providerReference'] = $provider['reference'];
            $mutable['releasedAt'] = Helpers::nowIso();
        });

        $this->notify((string) $payout['recipientId'], 'Payout released', $netAmount . ' released from ' . $group['name'] . '.', 'payout', 'payout-released-' . $payoutId);
        foreach ($group['memberIds'] as $memberId) {
            if ($memberId === $payout['recipientId']) {
                continue;
            }
            $this->notify((string) $memberId, 'Payout completed', $recipient['fullName'] . ' received payout in ' . $group['name'] . '.', 'payout', 'payout-complete-' . $payoutId . '-' . $memberId);
        }

        $this->logAudit($actorId, 'RELEASE_PAYOUT', 'payout', $payoutId, [
            'providerReference' => $provider['reference'],
            'netAmount' => $netAmount,
            'fee' => $fee,
        ]);
        $this->rollCycle((string) $group['id']);
        $this->reconcile();
        $this->persist();
        return ['mfaRequired' => false, 'payout' => $this->requirePayout($payoutId)];
    }

    /**
     * @return array<int,array<string,mixed>>
     */
    public function listChat(string $userId, string $groupId): array
    {
        $group = $this->requireGroup($groupId);
        Helpers::assert(in_array($userId, $group['memberIds'], true), 403, 'FORBIDDEN', 'Only members can access group chat.');
        $messages = array_values(array_filter($this->state['chats'], static fn (array $message): bool => $message['groupId'] === $groupId));
        usort($messages, static function (array $a, array $b): int {
            if ($a['pinned'] !== $b['pinned']) {
                return $a['pinned'] ? -1 : 1;
            }
            return strtotime((string) $a['createdAt']) <=> strtotime((string) $b['createdAt']);
        });
        return $messages;
    }

    /**
     * @param array<string,mixed> $input
     * @return array<string,mixed>
     */
    public function sendChat(string $userId, string $groupId, array $input): array
    {
        $group = $this->requireGroup($groupId);
        $actor = $this->requireUser($userId);
        Helpers::assert(in_array($userId, $group['memberIds'], true), 403, 'FORBIDDEN', 'Only members can send messages.');
        Helpers::assert(!((bool) $group['chatArchived']) && $group['status'] !== 'completed', 409, 'CHAT_ARCHIVED', 'Chat is archived.');
        $content = trim((string) ($input['content'] ?? ''));
        Helpers::assert($content !== '', 400, 'EMPTY_MESSAGE', 'Message cannot be empty.');
        $canModerate = $actor['role'] === 'admin' || $group['leaderId'] === $userId;
        $message = [
            'id' => Helpers::uid('msg'),
            'groupId' => $groupId,
            'userId' => $userId,
            'content' => $content,
            'type' => ($canModerate && (($input['announcement'] ?? false) === true)) ? 'announcement' : 'message',
            'pinned' => $canModerate && (($input['pin'] ?? false) === true),
            'createdAt' => Helpers::nowIso(),
        ];
        $this->state['chats'][] = $message;
        if ($message['type'] === 'announcement') {
            foreach ($group['memberIds'] as $memberId) {
                if ($memberId === $userId) {
                    continue;
                }
                $this->notify((string) $memberId, 'Announcement in ' . $group['name'], substr($content, 0, 150), 'chat', 'chat-announce-' . $message['id'] . '-' . $memberId);
            }
        }
        $this->logAudit($userId, 'SEND_CHAT_MESSAGE', 'chat', $message['id'], ['groupId' => $groupId]);
        $this->persist();
        return $message;
    }

    /**
     * @return array<string,mixed>
     */
    public function togglePin(string $actorId, string $messageId): array
    {
        $actor = $this->requireUser($actorId);
        $message = $this->firstWhere($this->state['chats'], static fn (array $candidate): bool => $candidate['id'] === $messageId);
        Helpers::assert($message !== null, 404, 'NOT_FOUND', 'Message not found.');
        $group = $this->requireGroup((string) $message['groupId']);
        Helpers::assert($actor['role'] === 'admin' || $group['leaderId'] === $actorId, 403, 'FORBIDDEN', 'Only admin/leader can pin.');
        $this->mutateChat($messageId, static function (array &$mutable): void {
            $mutable['pinned'] = !(bool) $mutable['pinned'];
        });
        $updated = $this->firstWhere($this->state['chats'], static fn (array $candidate): bool => $candidate['id'] === $messageId);
        $this->logAudit($actorId, 'TOGGLE_CHAT_PIN', 'chat', $messageId, ['pinned' => $updated['pinned'] ?? false]);
        $this->persist();
        return $updated ?? [];
    }

    /**
     * @return array<int,array<string,mixed>>
     */
    public function calendarEvents(string $userId): array
    {
        $events = [];
        foreach ($this->groupsForUser($userId) as $group) {
            $dueDate = Helpers::cycleDueDate((string) $group['startDate'], (int) $group['cycle']);
            $graceDate = Helpers::cycleGraceDate((string) $group['startDate'], (int) $group['cycle'], (int) $group['gracePeriodDays']);
            $payout = $this->currentPayout((string) $group['id'], (int) $group['cycle']);
            $events[] = [
                'id' => 'due-' . $group['id'] . '-' . $group['cycle'],
                'date' => $dueDate,
                'title' => 'Monthly contribution due',
                'type' => 'contribution_due',
                'groupId' => $group['id'],
                'groupName' => $group['name'],
            ];
            $events[] = [
                'id' => 'grace-' . $group['id'] . '-' . $group['cycle'],
                'date' => $graceDate,
                'title' => 'Grace deadline',
                'type' => 'grace_deadline',
                'groupId' => $group['id'],
                'groupName' => $group['name'],
            ];
            $events[] = [
                'id' => 'payout-' . $group['id'] . '-' . $group['cycle'],
                'date' => $dueDate,
                'title' => $payout !== null ? 'Payout ' . $payout['status'] : 'Payout checkpoint',
                'type' => 'payout_checkpoint',
                'groupId' => $group['id'],
                'groupName' => $group['name'],
            ];
        }
        usort($events, static fn (array $a, array $b): int => strtotime($a['date']) <=> strtotime($b['date']));
        return $events;
    }

    /**
     * @return array<int,array<string,mixed>>
     */
    public function userNotifications(string $userId): array
    {
        $notifications = array_values(array_filter($this->state['notifications'], static fn (array $notification): bool => $notification['userId'] === $userId));
        usort($notifications, static fn (array $a, array $b): int => strtotime($b['createdAt']) <=> strtotime($a['createdAt']));
        return $notifications;
    }

    public function markNotificationRead(string $userId, string $notificationId): void
    {
        $notification = $this->firstWhere($this->state['notifications'], static fn (array $candidate): bool => $candidate['id'] === $notificationId);
        Helpers::assert($notification !== null, 404, 'NOT_FOUND', 'Notification not found.');
        Helpers::assert($notification['userId'] === $userId, 403, 'FORBIDDEN', 'Cannot update another user notification.');
        $this->mutateNotification($notificationId, static function (array &$mutable): void {
            $mutable['read'] = true;
        });
        $this->persist();
    }

    public function markAllNotificationsRead(string $userId): void
    {
        foreach ($this->state['notifications'] as &$notification) {
            if ($notification['userId'] === $userId) {
                $notification['read'] = true;
            }
        }
        unset($notification);
        $this->persist();
    }

    /**
     * @param array<string,mixed> $input
     * @return array<string,mixed>
     */
    public function submitKyc(string $userId, array $input): array
    {
        $user = $this->requireUser($userId);
        Helpers::assert(
            trim((string) ($input['idType'] ?? '')) !== '' &&
            trim((string) ($input['idNumber'] ?? '')) !== '' &&
            trim((string) ($input['dob'] ?? '')) !== '' &&
            trim((string) ($input['selfieToken'] ?? '')) !== '',
            400,
            'INVALID_INPUT',
            'Missing KYC data.'
        );

        $kycCase = $this->kycProvider()->createCase([
            'userId' => $userId,
            'fullName' => (string) $user['fullName'],
            'email' => (string) $user['email'],
        ]);

        $this->mutateUser($userId, static function (array &$mutable) use ($input, $kycCase): void {
            $mutable['kyc'] = [
                'status' => 'pending',
                'idType' => trim((string) $input['idType']),
                'idNumberToken' => Helpers::tokenRef('id:' . trim((string) $input['idNumber'])),
                'dob' => trim((string) $input['dob']),
                'selfieToken' => Helpers::tokenRef('selfie:' . trim((string) $input['selfieToken'])),
                'addressToken' => trim((string) ($input['address'] ?? '')) !== '' ? Helpers::tokenRef('address:' . trim((string) $input['address'])) : null,
                'providerCaseId' => $kycCase['caseId'],
                'submittedAt' => Helpers::nowIso(),
            ];
        });

        foreach ($this->adminUsers() as $admin) {
            $this->notify((string) $admin['id'], 'KYC review required', $user['fullName'] . ' submitted KYC documents.', 'compliance', 'kyc-review-' . $userId . '-' . $admin['id']);
        }
        $this->logAudit($userId, 'SUBMIT_KYC', 'user', $userId, ['providerCaseId' => $kycCase['caseId']]);
        $this->reconcile();
        $this->persist();
        return [
            'status' => 'pending',
            'providerCaseId' => $kycCase['caseId'],
            'providerClientSecret' => $kycCase['clientSecret'],
            'mode' => $kycCase['mode'],
        ];
    }

    /**
     * @return array<string,mixed>
     */
    public function createKycSession(string $userId): array
    {
        $user = $this->requireUser($userId);
        return $this->kycProvider()->createCase([
            'userId' => $userId,
            'fullName' => (string) $user['fullName'],
            'email' => (string) $user['email'],
        ]);
    }

    /**
     * @param array<string,mixed> $input
     * @return array<string,mixed>
     */
    public function updateSecurity(string $userId, array $input, ?string $mfaChallengeId = null, ?string $mfaCode = null): array
    {
        $mfaResult = $this->assertMfa($userId, 'security_change', $mfaChallengeId, $mfaCode);
        if (!$mfaResult['verified']) {
            $this->persist();
            return ['mfaRequired' => true, 'challenge' => $mfaResult];
        }

        $mfaEnabled = (bool) ($input['mfaEnabled'] ?? false);
        $biometricEnabled = (bool) ($input['biometricEnabled'] ?? false);
        $this->mutateUser($userId, static function (array &$mutable) use ($mfaEnabled, $biometricEnabled): void {
            $mutable['mfaEnabled'] = $mfaEnabled;
            $mutable['biometricEnabled'] = $biometricEnabled;
        });
        $this->logAudit($userId, 'UPDATE_SECURITY_SETTINGS', 'user', $userId, [
            'mfaEnabled' => $mfaEnabled,
            'biometricEnabled' => $biometricEnabled,
        ]);
        $this->persist();

        return ['mfaRequired' => false, 'user' => $this->publicUser($userId)];
    }

    /**
     * @param array<string,mixed> $input
     * @return array<string,mixed>
     */
    public function addPaymentMethod(string $userId, array $input, ?string $mfaChallengeId = null, ?string $mfaCode = null): array
    {
        $mfaResult = $this->assertMfa($userId, 'payment_method_update', $mfaChallengeId, $mfaCode);
        if (!$mfaResult['verified']) {
            $this->persist();
            return ['mfaRequired' => true, 'challenge' => $mfaResult];
        }
        $type = (string) ($input['type'] ?? 'bank');
        Helpers::assert(in_array($type, ['bank', 'debit', 'paypal', 'cashapp'], true), 400, 'INVALID_METHOD', 'Invalid payment method type.');
        $label = trim((string) ($input['label'] ?? ''));
        $identifierTail = trim((string) ($input['identifierTail'] ?? ''));
        Helpers::assert($label !== '', 400, 'INVALID_INPUT', 'Payment label required.');
        Helpers::assert(strlen($identifierTail) >= 2, 400, 'INVALID_IDENTIFIER', 'Invalid identifier.');
        $providerToken = trim((string) ($input['providerToken'] ?? ''));
        $method = [
            'id' => Helpers::uid('pm'),
            'type' => $type,
            'label' => $label,
            'last4' => substr($identifierTail, -4),
            'tokenRef' => $providerToken !== '' ? $providerToken : Helpers::tokenRef($type . ':' . $label . ':' . $identifierTail),
            'autoDebit' => (bool) ($input['autoDebit'] ?? false),
            'createdAt' => Helpers::nowIso(),
        ];
        $this->mutateUser($userId, static function (array &$mutable) use ($method): void {
            $mutable['paymentMethods'][] = $method;
        });
        $this->logAudit($userId, 'ADD_PAYMENT_METHOD', 'payment_method', $method['id'], ['type' => $type]);
        $this->persist();
        return ['mfaRequired' => false, 'paymentMethod' => $method];
    }

    /**
     * @return array<string,mixed>
     */
    public function removePaymentMethod(string $userId, string $methodId, ?string $mfaChallengeId = null, ?string $mfaCode = null): array
    {
        $mfaResult = $this->assertMfa($userId, 'payment_method_update', $mfaChallengeId, $mfaCode);
        if (!$mfaResult['verified']) {
            $this->persist();
            return ['mfaRequired' => true, 'challenge' => $mfaResult];
        }
        $user = $this->requireUser($userId);
        $exists = $this->firstWhere($user['paymentMethods'], static fn (array $method): bool => $method['id'] === $methodId);
        Helpers::assert($exists !== null, 404, 'NOT_FOUND', 'Payment method not found.');
        $this->mutateUser($userId, static function (array &$mutable) use ($methodId): void {
            $mutable['paymentMethods'] = array_values(array_filter(
                $mutable['paymentMethods'],
                static fn (array $method): bool => $method['id'] !== $methodId
            ));
        });
        $this->logAudit($userId, 'REMOVE_PAYMENT_METHOD', 'payment_method', $methodId, []);
        $this->persist();
        return ['mfaRequired' => false];
    }

    public function removeDevice(string $userId, string $deviceId): void
    {
        $this->mutateUser($userId, static function (array &$mutable) use ($deviceId): void {
            $mutable['knownDevices'] = array_values(array_filter(
                $mutable['knownDevices'],
                static fn (array $device): bool => $device['id'] !== $deviceId
            ));
        });
        $this->logAudit($userId, 'REMOVE_TRUSTED_DEVICE', 'device', $deviceId, []);
        $this->persist();
    }

    /**
     * @return array<string,mixed>
     */
    public function submitDispute(string $userId, string $groupId, string $summary): array
    {
        $group = $this->requireGroup($groupId);
        Helpers::assert(in_array($userId, $group['memberIds'], true), 403, 'FORBIDDEN', 'Only members can submit disputes.');
        $summaryText = trim($summary);
        Helpers::assert($summaryText !== '', 400, 'INVALID_INPUT', 'Summary cannot be empty.');
        $dispute = [
            'id' => Helpers::uid('dispute'),
            'groupId' => $groupId,
            'reporterId' => $userId,
            'summary' => $summaryText,
            'status' => 'open',
            'createdAt' => Helpers::nowIso(),
        ];
        $this->state['disputes'][] = $dispute;
        $reporter = $this->requireUser($userId);
        $this->notify((string) $group['leaderId'], 'Dispute filed', $reporter['fullName'] . ' filed dispute in ' . $group['name'] . '.', 'dispute', 'dispute-' . $dispute['id'] . '-leader');
        foreach ($this->adminUsers() as $admin) {
            $this->notify((string) $admin['id'], 'Dispute requires review', 'Dispute created in ' . $group['name'] . '.', 'dispute', 'dispute-' . $dispute['id'] . '-' . $admin['id']);
        }
        $this->logAudit($userId, 'FILE_DISPUTE', 'dispute', $dispute['id'], []);
        $this->persist();
        return $dispute;
    }

    /**
     * @return array<string,mixed>
     */
    public function adminOverview(string $userId): array
    {
        $user = $this->requireUser($userId);
        Helpers::assert($user['role'] === 'admin', 403, 'FORBIDDEN', 'Admin role required.');
        return [
            'pendingKyc' => array_values(array_filter($this->state['users'], static fn (array $candidate): bool => ($candidate['kyc']['status'] ?? 'unverified') === 'pending')),
            'lateContributions' => array_values(array_filter($this->state['contributions'], static fn (array $entry): bool => $entry['status'] === 'late')),
            'openDisputes' => array_values(array_filter($this->state['disputes'], static fn (array $dispute): bool => $dispute['status'] === 'open')),
            'fraudFlags' => $this->state['fraudFlags'],
            'groups' => $this->state['groups'],
            'recentAuditLogs' => array_values(array_reverse(array_slice($this->state['auditLogs'], -50))),
        ];
    }

    /**
     * @return array<string,mixed>
     */
    public function reviewKyc(string $adminId, string $targetUserId, string $status): array
    {
        $admin = $this->requireUser($adminId);
        Helpers::assert($admin['role'] === 'admin', 403, 'FORBIDDEN', 'Admin role required.');
        Helpers::assert(in_array($status, ['verified', 'rejected'], true), 400, 'INVALID_STATUS', 'Invalid KYC status.');
        $this->mutateUser($targetUserId, static function (array &$mutable) use ($status): void {
            $mutable['kyc']['status'] = $status;
            $mutable['verifiedBadge'] = $status === 'verified';
        });
        $this->notify($targetUserId, 'KYC status updated', 'Your KYC status is now ' . $status . '.', 'compliance', 'kyc-status-' . $targetUserId . '-' . $status . '-' . time());
        $this->logAudit($adminId, 'REVIEW_KYC', 'user', $targetUserId, ['status' => $status]);
        $this->reconcile();
        $this->persist();
        return $this->requireUser($targetUserId);
    }

    /**
     * @param array<string,string> $input
     * @return array<string,mixed>
     */
    public function createFraudFlag(string $adminId, array $input): array
    {
        $admin = $this->requireUser($adminId);
        Helpers::assert($admin['role'] === 'admin', 403, 'FORBIDDEN', 'Admin role required.');
        $targetType = (string) ($input['targetType'] ?? '');
        Helpers::assert(in_array($targetType, ['user', 'group', 'transaction'], true), 400, 'INVALID_TARGET_TYPE', 'Invalid target type.');
        $targetId = trim((string) ($input['targetId'] ?? ''));
        $reason = trim((string) ($input['reason'] ?? ''));
        Helpers::assert($targetId !== '' && $reason !== '', 400, 'INVALID_INPUT', 'Target and reason required.');
        $flag = [
            'id' => Helpers::uid('flag'),
            'targetType' => $targetType,
            'targetId' => $targetId,
            'reason' => $reason,
            'createdBy' => $adminId,
            'createdAt' => Helpers::nowIso(),
        ];
        $this->state['fraudFlags'][] = $flag;
        $this->logAudit($adminId, 'CREATE_FRAUD_FLAG', 'flag', $flag['id'], $input);
        $this->persist();
        return $flag;
    }

    /**
     * @return array<string,mixed>
     */
    public function resolveDispute(string $actorId, string $disputeId): array
    {
        $actor = $this->requireUser($actorId);
        $dispute = $this->firstWhere($this->state['disputes'], static fn (array $candidate): bool => $candidate['id'] === $disputeId);
        Helpers::assert($dispute !== null, 404, 'NOT_FOUND', 'Dispute not found.');
        $group = $this->requireGroup((string) $dispute['groupId']);
        Helpers::assert($actor['role'] === 'admin' || $group['leaderId'] === $actorId, 403, 'FORBIDDEN', 'Only admin or leader can resolve.');
        $this->mutateDispute($disputeId, static function (array &$mutable) use ($actor): void {
            $mutable['status'] = 'resolved';
            $mutable['resolvedAt'] = Helpers::nowIso();
            $mutable['resolution'] = 'Resolved by ' . $actor['fullName'];
        });
        $updated = $this->firstWhere($this->state['disputes'], static fn (array $candidate): bool => $candidate['id'] === $disputeId);
        $this->notify((string) $dispute['reporterId'], 'Dispute resolved', 'Your dispute in ' . $group['name'] . ' has been resolved.', 'dispute', 'dispute-resolved-' . $disputeId);
        $this->logAudit($actorId, 'RESOLVE_DISPUTE', 'dispute', $disputeId, []);
        $this->persist();
        return $updated ?? [];
    }

    /**
     * @return array<string,mixed>
     */
    public function updateGroupStatus(string $adminId, string $groupId, string $status): array
    {
        $admin = $this->requireUser($adminId);
        Helpers::assert($admin['role'] === 'admin', 403, 'FORBIDDEN', 'Admin role required.');
        Helpers::assert(in_array($status, ['active', 'suspended'], true), 400, 'INVALID_STATUS', 'Invalid group status.');
        $this->mutateGroup($groupId, static function (array &$mutable) use ($status): void {
            $mutable['status'] = $status;
        });
        $group = $this->requireGroup($groupId);
        $this->notifyGroup($group, $status === 'active' ? 'Group reactivated' : 'Group suspended', $status === 'active' ? $group['name'] . ' is active again.' : $group['name'] . ' is suspended pending compliance review.', 'compliance', $status . '-' . $groupId . '-' . time());
        $this->logAudit($adminId, 'UPDATE_GROUP_STATUS', 'group', $groupId, ['status' => $status]);
        $this->persist();
        return $group;
    }

    public function exportReport(string $adminId, string $format): string
    {
        $admin = $this->requireUser($adminId);
        Helpers::assert($admin['role'] === 'admin', 403, 'FORBIDDEN', 'Admin role required.');
        $payload = [
            'generatedAt' => Helpers::nowIso(),
            'users' => array_map(static fn (array $user): array => [
                'id' => $user['id'],
                'fullName' => $user['fullName'],
                'email' => $user['email'],
                'role' => $user['role'],
                'kycStatus' => $user['kyc']['status'],
                'trustScoreInternal' => $user['metrics']['internalTrustScore'],
            ], $this->state['users']),
            'groups' => array_map(static fn (array $group): array => [
                'id' => $group['id'],
                'name' => $group['name'],
                'status' => $group['status'],
                'members' => count($group['memberIds']),
                'cycle' => $group['cycle'],
            ], $this->state['groups']),
            'contributions' => count($this->state['contributions']),
            'payouts' => count($this->state['payouts']),
            'disputes' => count($this->state['disputes']),
            'fraudFlags' => count($this->state['fraudFlags']),
        ];
        if ($format === 'csv') {
            $lines = ['type,id,name,status,metricA,metricB'];
            foreach ($payload['users'] as $user) {
                $lines[] = sprintf(
                    'user,%s,"%s",%s,%s,%s',
                    $user['id'],
                    str_replace('"', '""', (string) $user['fullName']),
                    $user['kycStatus'],
                    $user['trustScoreInternal'],
                    $user['role']
                );
            }
            foreach ($payload['groups'] as $group) {
                $lines[] = sprintf(
                    'group,%s,"%s",%s,%d,%d',
                    $group['id'],
                    str_replace('"', '""', (string) $group['name']),
                    $group['status'],
                    $group['members'],
                    $group['cycle']
                );
            }
            return implode("\n", $lines);
        }
        return (string) json_encode($payload, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR);
    }

    public function exportAudit(string $adminId): string
    {
        $admin = $this->requireUser($adminId);
        Helpers::assert($admin['role'] === 'admin', 403, 'FORBIDDEN', 'Admin role required.');
        return (string) json_encode([
            'generatedAt' => Helpers::nowIso(),
            'entries' => $this->state['auditLogs'],
        ], JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR);
    }

    public function mfaPreview(string $challengeId): ?string
    {
        $challenge = $this->firstWhere($this->state['mfaChallenges'], static fn (array $candidate): bool => $candidate['id'] === $challengeId);
        return $challenge['code'] ?? null;
    }

    /**
     * @return array<int,array<string,mixed>>
     */
    private function groupsForUser(string $userId): array
    {
        return array_values(array_filter($this->state['groups'], static fn (array $group): bool => in_array($userId, $group['memberIds'], true)));
    }

    /**
     * @param array<string,mixed> $group
     */
    private function eligibleRecipient(array $group, int $cycle): string
    {
        $order = $group['payoutOrder'];
        $members = $group['memberIds'];
        $rotation = $order !== [] ? $order[($cycle - 1) % count($order)] : $members[($cycle - 1) % count($members)];
        $logic = (string) $group['payoutOrderLogic'];
        if ($logic === 'fixed') {
            return (string) $rotation;
        }
        if ($logic === 'voting') {
            $votes = [];
            foreach ($this->state['payoutVotes'] as $vote) {
                if ($vote['groupId'] === $group['id'] && (int) $vote['cycle'] === $cycle) {
                    $candidate = (string) $vote['candidateId'];
                    $votes[$candidate] = ($votes[$candidate] ?? 0) + 1;
                }
            }
            if ($votes === []) {
                return (string) $rotation;
            }
            arsort($votes);
            return (string) array_key_first($votes);
        }
        if ($logic === 'priority') {
            $claims = array_values(array_filter(
                $this->state['priorityClaims'],
                static fn (array $claim): bool => $claim['groupId'] === $group['id'] && (int) $claim['cycle'] === $cycle
            ));
            usort($claims, static function (array $a, array $b): int {
                if ((int) $a['weight'] !== (int) $b['weight']) {
                    return (int) $b['weight'] <=> (int) $a['weight'];
                }
                return strtotime((string) $a['createdAt']) <=> strtotime((string) $b['createdAt']);
            });
            if ($claims === []) {
                return (string) $rotation;
            }
            return (string) $claims[0]['userId'];
        }
        return (string) $rotation;
    }

    private function allContributionsPaid(string $groupId, int $cycle): bool
    {
        $entries = $this->cycleContributions($groupId, $cycle);
        if ($entries === []) {
            return false;
        }
        foreach ($entries as $entry) {
            if ($entry['status'] !== 'paid') {
                return false;
            }
        }
        return true;
    }

    /**
     * @return array<int,array<string,mixed>>
     */
    private function cycleContributions(string $groupId, int $cycle): array
    {
        return array_values(array_filter(
            $this->state['contributions'],
            static fn (array $entry): bool => $entry['groupId'] === $groupId && (int) $entry['cycle'] === $cycle
        ));
    }

    /**
     * @return array<string,mixed>|null
     */
    private function currentPayout(string $groupId, int $cycle): ?array
    {
        return $this->firstWhere($this->state['payouts'], static fn (array $payout): bool => $payout['groupId'] === $groupId && (int) $payout['cycle'] === $cycle);
    }

    /**
     * @param array<string,mixed> $group
     * @param array<string,mixed> $payout
     */
    private function refreshPayoutStatus(array $group, array &$payout): void
    {
        $leaderApproved = $group['requiresLeaderApproval'] ? isset($payout['leaderApprovedBy']) : true;
        $threshold = (float) ($this->state['meta']['adminPayoutApprovalThreshold'] ?? 2000);
        $adminRequired = ((float) $payout['amount']) >= $threshold;
        $adminApproved = $adminRequired ? isset($payout['adminApprovedBy']) : true;
        $payout['status'] = $leaderApproved && $adminApproved ? 'approved' : 'requested';
    }

    private function rollCycle(string $groupId): void
    {
        $group = $this->requireGroup($groupId);
        $nextCycle = ((int) $group['cycle']) + 1;
        if ($nextCycle > (int) $group['totalMembers']) {
            $this->mutateGroup($groupId, static function (array &$mutable): void {
                $mutable['cycle'] = (int) $mutable['cycle'] + 1;
                $mutable['status'] = 'completed';
                $mutable['chatArchived'] = true;
            });
            $updated = $this->requireGroup($groupId);
            $this->notifyGroup($updated, 'Group cycle completed', $updated['name'] . ' completed all payout cycles.', 'milestone', 'group-complete-' . $groupId);
            return;
        }

        $this->mutateGroup($groupId, static function (array &$mutable): void {
            $mutable['cycle'] = (int) $mutable['cycle'] + 1;
        });
        $updated = $this->requireGroup($groupId);
        $this->ensureCycleContributions($updated);
        $this->notifyGroup($updated, 'New cycle started', $updated['name'] . ' moved to cycle ' . $updated['cycle'] . '.', 'milestone', 'group-cycle-' . $groupId . '-' . $updated['cycle']);
    }

    /**
     * @param array<string,mixed> $group
     */
    private function ensureCycleContributions(array $group): void
    {
        $dueDate = Helpers::cycleDueDate((string) $group['startDate'], (int) $group['cycle']);
        foreach ($group['memberIds'] as $memberId) {
            $exists = $this->firstWhere(
                $this->state['contributions'],
                static fn (array $entry): bool => $entry['groupId'] === $group['id'] && (int) $entry['cycle'] === (int) $group['cycle'] && $entry['userId'] === $memberId
            );
            if ($exists !== null) {
                continue;
            }
            $this->state['contributions'][] = [
                'id' => Helpers::uid('ctr'),
                'groupId' => $group['id'],
                'cycle' => $group['cycle'],
                'userId' => $memberId,
                'amount' => (float) $group['contributionAmount'],
                'dueDate' => $dueDate,
                'status' => 'pending',
                'autoDebit' => false,
                'createdAt' => Helpers::nowIso(),
            ];
        }
    }

    private function addMemberToGroup(string $groupId, string $userId): void
    {
        $this->mutateGroup($groupId, static function (array &$mutable) use ($userId): void {
            if (!in_array($userId, $mutable['memberIds'], true)) {
                $mutable['memberIds'][] = $userId;
            }
            if (!in_array($userId, $mutable['payoutOrder'], true)) {
                $mutable['payoutOrder'][] = $userId;
            }
        });
        $group = $this->requireGroup($groupId);
        $this->ensureCycleContributions($group);
        $this->notify($userId, 'Added to group', 'You joined ' . $group['name'] . '.', 'group', 'group-join-' . $groupId . '-' . $userId);
    }

    /**
     * @return array<string,mixed>
     */
    private function assertMfa(string $userId, string $purpose, ?string $challengeId, ?string $code): array
    {
        $user = $this->requireUser($userId);
        $requires = in_array($purpose, Constants::MFA_REQUIRED_ACTIONS, true) && ((bool) $user['mfaEnabled']);
        if (!$requires) {
            return ['verified' => true];
        }
        if ($challengeId === null || $code === null || trim($challengeId) === '' || trim($code) === '') {
            return $this->createMfaChallenge($userId, $purpose);
        }
        $this->verifyMfaChallenge($challengeId, $code, $purpose);
        return ['verified' => true];
    }

    /**
     * @return array<string,mixed>
     */
    private function createMfaChallenge(string $userId, string $purpose): array
    {
        $challenge = [
            'id' => Helpers::uid('mfa'),
            'userId' => $userId,
            'purpose' => $purpose,
            'code' => Helpers::generateMfaCode(),
            'expiresAt' => Helpers::addMinutes(Helpers::nowIso(), (int) env('MFA_TTL_MINUTES', 10)),
        ];
        $this->state['mfaChallenges'][] = $challenge;
        $exposeCodes = Helpers::asBool(env('EXPOSE_MFA_CODES', true), true);
        return [
            'verified' => false,
            'challengeId' => $challenge['id'],
            'expiresAt' => $challenge['expiresAt'],
            'demoCode' => $exposeCodes ? $challenge['code'] : null,
        ];
    }

    /**
     * @return array<string,mixed>
     */
    private function verifyMfaChallenge(string $challengeId, string $code, string $expectedPurpose): array
    {
        $challenge = $this->firstWhere($this->state['mfaChallenges'], static fn (array $entry): bool => $entry['id'] === $challengeId);
        Helpers::assert($challenge !== null, 401, 'INVALID_MFA_CHALLENGE', 'MFA challenge not found.');
        Helpers::assert($challenge['purpose'] === $expectedPurpose, 401, 'INVALID_MFA_PURPOSE', 'MFA challenge purpose mismatch.');
        Helpers::assert(strtotime((string) $challenge['expiresAt']) > time(), 401, 'MFA_EXPIRED', 'MFA challenge expired.');
        Helpers::assert((string) $challenge['code'] === $code, 401, 'INVALID_MFA_CODE', 'Invalid MFA code.');
        $this->state['mfaChallenges'] = array_values(array_filter(
            $this->state['mfaChallenges'],
            static fn (array $entry): bool => $entry['id'] !== $challengeId
        ));
        return $challenge;
    }

    /**
     * @return array<string,mixed>
     */
    private function issueSession(string $userId, string $deviceId): array
    {
        $token = Helpers::uid('sess');
        $now = Helpers::nowIso();
        $hours = (int) env('SESSION_TTL_HOURS', 24);
        $expiresAt = Helpers::addHours($now, $hours);
        $this->state['sessions'] = array_values(array_filter(
            $this->state['sessions'],
            static fn (array $session): bool => $session['userId'] !== $userId
        ));
        $this->state['sessions'][] = [
            'token' => $token,
            'userId' => $userId,
            'deviceId' => $deviceId,
            'createdAt' => $now,
            'expiresAt' => $expiresAt,
        ];
        $this->mutateUser($userId, static function (array &$mutable): void {
            $mutable['lastLoginAt'] = Helpers::nowIso();
        });
        return [
            'accessToken' => $token,
            'expiresAt' => $expiresAt,
        ];
    }

    private function touchDevice(string $userId, string $deviceId, string $label): void
    {
        $this->mutateUser($userId, static function (array &$mutable) use ($deviceId, $label): void {
            $found = false;
            foreach ($mutable['knownDevices'] as &$device) {
                if ($device['id'] === $deviceId) {
                    $device['lastSeenAt'] = Helpers::nowIso();
                    $found = true;
                }
            }
            unset($device);
            if (!$found) {
                $mutable['knownDevices'][] = [
                    'id' => $deviceId,
                    'label' => $label,
                    'lastSeenAt' => Helpers::nowIso(),
                ];
            }
        });
    }

    /**
     * @param array<string,mixed> $actor
     * @param array<string,mixed> $group
     */
    private function assertGroupManager(array $actor, array $group): void
    {
        Helpers::assert($actor['role'] === 'admin' || $actor['id'] === $group['leaderId'], 403, 'FORBIDDEN', 'Group manager role required.');
    }

    /**
     * @return array<int,array<string,mixed>>
     */
    private function adminUsers(): array
    {
        return array_values(array_filter($this->state['users'], static fn (array $user): bool => $user['role'] === 'admin'));
    }

    /**
     * @param array<string,mixed> $group
     */
    private function notifyGroup(array $group, string $title, string $body, string $type, string $dedupeBase): void
    {
        foreach ($group['memberIds'] as $memberId) {
            $this->notify((string) $memberId, $title, $body, $type, $dedupeBase . '-' . $memberId);
        }
    }

    private function notify(string $userId, string $title, string $body, string $type, ?string $dedupeKey = null): void
    {
        if ($dedupeKey !== null) {
            $existing = $this->firstWhere($this->state['notifications'], static fn (array $notification): bool => $notification['userId'] === $userId && ($notification['dedupeKey'] ?? null) === $dedupeKey);
            if ($existing !== null) {
                return;
            }
        }
        $this->state['notifications'][] = [
            'id' => Helpers::uid('note'),
            'userId' => $userId,
            'title' => $title,
            'body' => $body,
            'type' => $type,
            'dedupeKey' => $dedupeKey,
            'read' => false,
            'createdAt' => Helpers::nowIso(),
        ];
    }

    /**
     * @param array<string,mixed> $metadata
     */
    private function logAudit(string $actorId, string $action, string $targetType, string $targetId, array $metadata): void
    {
        $previous = $this->state['auditLogs'][count($this->state['auditLogs']) - 1]['entryHash'] ?? 'GENESIS';
        $timestamp = Helpers::nowIso();
        $payload = $previous . '|' . $timestamp . '|' . $actorId . '|' . $action . '|' . $targetType . '|' . $targetId . '|' . json_encode($metadata);
        $entryHash = Helpers::hashValue($payload);
        $this->state['auditLogs'][] = [
            'id' => Helpers::uid('audit'),
            'actorId' => $actorId,
            'action' => $action,
            'targetType' => $targetType,
            'targetId' => $targetId,
            'metadata' => $metadata,
            'timestamp' => $timestamp,
            'previousHash' => $previous,
            'entryHash' => $entryHash,
        ];
    }

    private function reconcile(): void
    {
        foreach ($this->state['groups'] as &$group) {
            $group['payoutOrder'] = array_values(array_filter(
                $group['payoutOrder'],
                static fn (string $memberId): bool => in_array($memberId, $group['memberIds'], true)
            ));
            foreach ($group['memberIds'] as $memberId) {
                if (!in_array($memberId, $group['payoutOrder'], true)) {
                    $group['payoutOrder'][] = $memberId;
                }
            }
            $this->ensureCycleContributions($group);
            if ($group['status'] === 'completed') {
                $group['chatArchived'] = true;
            }
        }
        unset($group);

        foreach ($this->state['contributions'] as &$entry) {
            if ($entry['status'] === 'paid') {
                continue;
            }
            $group = $this->groupById((string) $entry['groupId']);
            if ($group === null || $group['status'] !== 'active') {
                continue;
            }
            $graceDate = Helpers::cycleGraceDate((string) $group['startDate'], (int) $entry['cycle'], (int) $group['gracePeriodDays']);
            if (time() > strtotime($graceDate) && $entry['status'] !== 'late') {
                $entry['status'] = 'late';
                $user = $this->requireUser((string) $entry['userId']);
                $this->notify((string) $group['leaderId'], 'Late contribution alert', $user['fullName'] . ' is late for ' . $group['name'] . '.', 'compliance', 'late-' . $entry['id']);
            }
            $daysToDue = (int) floor((strtotime((string) $entry['dueDate']) - time()) / 86400);
            if (($entry['reminderSentAt'] ?? null) === null && $daysToDue <= 3 && $daysToDue >= 0) {
                $this->notify((string) $entry['userId'], 'Contribution due reminder', 'Your contribution is due soon in ' . $group['name'] . '.', 'reminder', 'auto-reminder-' . $entry['id']);
                $entry['reminderSentAt'] = Helpers::nowIso();
            }
        }
        unset($entry);

        foreach ($this->state['users'] as &$user) {
            $paidCount = count(array_filter(
                $this->state['contributions'],
                static fn (array $entry): bool => $entry['userId'] === $user['id'] && $entry['status'] === 'paid'
            ));
            $lateCount = count(array_filter(
                $this->state['contributions'],
                static fn (array $entry): bool => $entry['userId'] === $user['id'] && $entry['status'] === 'late'
            ));
            $completedGroups = count(array_filter(
                $this->state['groups'],
                static fn (array $group): bool => $group['status'] === 'completed' && in_array($user['id'], $group['memberIds'], true)
            ));
            $score = max(
                0,
                min(
                    100,
                    45 +
                    min(20, $paidCount * 2) +
                    (($user['kyc']['status'] ?? 'unverified') === 'verified' ? 15 : 0) +
                    min(12, $completedGroups * 3) -
                    min(20, $lateCount * 4)
                )
            );
            $user['metrics']['paidContributions'] = $paidCount;
            $user['metrics']['completedGroups'] = $completedGroups;
            $user['metrics']['internalTrustScore'] = $score;
        }
        unset($user);
    }

    /**
     * @return array<string,mixed>
     */
    private function publicUser(string $userId): array
    {
        $user = $this->requireUser($userId);
        return [
            'id' => $user['id'],
            'fullName' => $user['fullName'],
            'email' => $user['email'],
            'phone' => $user['phone'],
            'role' => $user['role'],
            'status' => $user['status'],
            'verifiedBadge' => $user['verifiedBadge'],
            'biometricEnabled' => $user['biometricEnabled'],
            'mfaEnabled' => $user['mfaEnabled'],
            'kyc' => $user['kyc'],
            'metrics' => $user['metrics'],
            'paymentMethods' => $user['paymentMethods'],
            'knownDevices' => $user['knownDevices'],
        ];
    }

    /**
     * @return array<string,mixed>
     */
    private function requireUser(string $userId): array
    {
        $user = $this->firstWhere($this->state['users'], static fn (array $candidate): bool => $candidate['id'] === $userId);
        Helpers::assert($user !== null, 404, 'NOT_FOUND', 'User not found.');
        return $user;
    }

    /**
     * @return array<string,mixed>|null
     */
    private function findUserByEmail(string $email): ?array
    {
        return $this->firstWhere($this->state['users'], static fn (array $candidate): bool => $candidate['email'] === $email);
    }

    /**
     * @return array<string,mixed>
     */
    private function requireGroup(string $groupId): array
    {
        $group = $this->groupById($groupId);
        Helpers::assert($group !== null, 404, 'NOT_FOUND', 'Group not found.');
        return $group;
    }

    /**
     * @return array<string,mixed>|null
     */
    private function groupById(string $groupId): ?array
    {
        return $this->firstWhere($this->state['groups'], static fn (array $group): bool => $group['id'] === $groupId);
    }

    /**
     * @return array<string,mixed>|null
     */
    private function findContribution(string $contributionId): ?array
    {
        return $this->firstWhere($this->state['contributions'], static fn (array $entry): bool => $entry['id'] === $contributionId);
    }

    /**
     * @return array<string,mixed>
     */
    private function requirePayout(string $payoutId): array
    {
        $payout = $this->firstWhere($this->state['payouts'], static fn (array $entry): bool => $entry['id'] === $payoutId);
        Helpers::assert($payout !== null, 404, 'NOT_FOUND', 'Payout not found.');
        return $payout;
    }

    /**
     * @param callable(array<string,mixed>&):void $callback
     */
    private function mutateUser(string $userId, callable $callback): void
    {
        foreach ($this->state['users'] as &$user) {
            if ($user['id'] === $userId) {
                $callback($user);
                break;
            }
        }
        unset($user);
    }

    /**
     * @param callable(array<string,mixed>&):void $callback
     */
    private function mutateGroup(string $groupId, callable $callback): void
    {
        foreach ($this->state['groups'] as &$group) {
            if ($group['id'] === $groupId) {
                $callback($group);
                break;
            }
        }
        unset($group);
    }

    /**
     * @param callable(array<string,mixed>&):void $callback
     */
    private function mutateContribution(string $contributionId, callable $callback): void
    {
        foreach ($this->state['contributions'] as &$entry) {
            if ($entry['id'] === $contributionId) {
                $callback($entry);
                break;
            }
        }
        unset($entry);
    }

    /**
     * @param callable(array<string,mixed>&):void $callback
     */
    private function mutatePayout(string $payoutId, callable $callback): void
    {
        foreach ($this->state['payouts'] as &$payout) {
            if ($payout['id'] === $payoutId) {
                $callback($payout);
                break;
            }
        }
        unset($payout);
    }

    /**
     * @param callable(array<string,mixed>&):void $callback
     */
    private function mutateChat(string $messageId, callable $callback): void
    {
        foreach ($this->state['chats'] as &$message) {
            if ($message['id'] === $messageId) {
                $callback($message);
                break;
            }
        }
        unset($message);
    }

    /**
     * @param callable(array<string,mixed>&):void $callback
     */
    private function mutateNotification(string $notificationId, callable $callback): void
    {
        foreach ($this->state['notifications'] as &$notification) {
            if ($notification['id'] === $notificationId) {
                $callback($notification);
                break;
            }
        }
        unset($notification);
    }

    /**
     * @param callable(array<string,mixed>&):void $callback
     */
    private function mutateDispute(string $disputeId, callable $callback): void
    {
        foreach ($this->state['disputes'] as &$dispute) {
            if ($dispute['id'] === $disputeId) {
                $callback($dispute);
                break;
            }
        }
        unset($dispute);
    }

    /**
     * @param array<int,array<string,mixed>> $items
     * @param callable(array<string,mixed>):bool $predicate
     * @return array<string,mixed>|null
     */
    private function firstWhere(array $items, callable $predicate): ?array
    {
        foreach ($items as $item) {
            if ($predicate($item)) {
                return $item;
            }
        }
        return null;
    }

    private function paymentGateway(): PaymentGatewayInterface
    {
        return $this->paymentGateway ?? new PaymentGatewayManager();
    }

    private function kycProvider(): KycProviderInterface
    {
        return $this->kycProvider ?? new KycProviderManager();
    }

    private function persist(): void
    {
        $this->repository->set($this->state);
    }
}
