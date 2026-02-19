<?php

declare(strict_types=1);

namespace Tests\Feature;

use App\Services\Domain\DomainEngineService;
use App\Services\Domain\DomainStateRepository;
use App\Services\Providers\KycProviderInterface;
use App\Services\Providers\PaymentGatewayInterface;
use App\Support\Domain\Exceptions\DomainHttpException;
use PHPUnit\Framework\TestCase;

final class DomainEngineParityTest extends TestCase
{
    private DomainEngineService $engine;

    protected function setUp(): void
    {
        parent::setUp();
        putenv('EXPOSE_MFA_CODES=true');
        putenv('PAYMENTS_LIVE_MODE=false');
        putenv('KYC_LIVE_MODE=false');
        putenv('MFA_TTL_MINUTES=10');
        putenv('SESSION_TTL_HOURS=24');
        putenv('PLATFORM_FEE_RATE=0.015');
        putenv('ADMIN_PAYOUT_APPROVAL_THRESHOLD=2000');

        $this->engine = new DomainEngineService(
            new DomainStateRepository(),
            new FakePaymentGateway(),
            new FakeKycProvider()
        );
        $this->engine->resetStateForTests();
    }

    public function testLoginMfaAndDashboardFlow(): void
    {
        $login = $this->engine->login([
            'email' => 'admin@susukonnect.app',
            'password' => 'Admin@2026',
            'deviceId' => 'ios-admin-device',
        ]);
        self::assertTrue((bool) $login['requiresMfa']);
        $challenge = $login['challenge'];
        self::assertNotEmpty($challenge['challengeId']);
        self::assertSame(6, strlen((string) $challenge['demoCode']));

        $verified = $this->engine->verifyLoginMfa([
            'challengeId' => (string) $challenge['challengeId'],
            'code' => (string) $challenge['demoCode'],
            'deviceId' => 'ios-admin-device',
        ]);
        self::assertArrayHasKey('tokens', $verified);
        self::assertArrayHasKey('user', $verified);
        self::assertSame('admin', $verified['user']['role']);

        $dashboard = $this->engine->dashboard((string) $verified['user']['id']);
        self::assertArrayHasKey('summary', $dashboard);
        self::assertArrayHasKey('upcomingEvents', $dashboard);
        self::assertArrayHasKey('recentAudit', $dashboard);
    }

    public function testContributionAndPayoutLifecycleParity(): void
    {
        $leader = $this->completeLogin('leader@susukonnect.app', 'Leader@2026', 'leader-device');
        $member = $this->completeLogin('member@susukonnect.app', 'Member@2026', 'member-device');

        $memberContributions = $this->engine->listContributions((string) $member['user']['id'], 'grp_fixed_001');
        $pending = array_values(array_filter(
            $memberContributions,
            static fn (array $entry): bool => $entry['userId'] === 'usr_member' && $entry['status'] !== 'paid'
        ));
        self::assertNotEmpty($pending);
        $targetContribution = $pending[0];

        $firstPay = $this->engine->payContribution((string) $member['user']['id'], (string) $targetContribution['id'], [
            'methodId' => 'pm_member_debit',
            'enableAutoDebit' => false,
        ]);
        self::assertTrue((bool) $firstPay['mfaRequired']);
        $payChallenge = $firstPay['challenge'];

        $paid = $this->engine->payContribution((string) $member['user']['id'], (string) $targetContribution['id'], [
            'methodId' => 'pm_member_debit',
            'enableAutoDebit' => false,
            'mfaChallengeId' => $payChallenge['challengeId'],
            'mfaCode' => $payChallenge['demoCode'],
        ]);
        self::assertFalse((bool) $paid['mfaRequired']);
        self::assertSame('paid', $paid['contribution']['status']);

        $payout = $this->engine->requestPayout((string) $leader['user']['id'], 'grp_fixed_001', 'Emergency');
        self::assertSame('requested', $payout['status']);

        $approvalInit = $this->engine->approvePayout((string) $leader['user']['id'], (string) $payout['id'], []);
        self::assertTrue((bool) $approvalInit['mfaRequired']);
        $approvalChallenge = $approvalInit['challenge'];
        $approved = $this->engine->approvePayout((string) $leader['user']['id'], (string) $payout['id'], [
            'mfaChallengeId' => $approvalChallenge['challengeId'],
            'mfaCode' => $approvalChallenge['demoCode'],
        ]);
        self::assertFalse((bool) $approved['mfaRequired']);
        self::assertSame('approved', $approved['payout']['status']);

        $confirmInit = $this->engine->confirmPayoutRecipient((string) $leader['user']['id'], (string) $payout['id'], []);
        self::assertTrue((bool) $confirmInit['mfaRequired']);
        $confirmChallenge = $confirmInit['challenge'];
        $confirmed = $this->engine->confirmPayoutRecipient((string) $leader['user']['id'], (string) $payout['id'], [
            'mfaChallengeId' => $confirmChallenge['challengeId'],
            'mfaCode' => $confirmChallenge['demoCode'],
        ]);
        self::assertFalse((bool) $confirmed['mfaRequired']);
        self::assertTrue((bool) $confirmed['payout']['recipientMfaConfirmed']);

        $releaseInit = $this->engine->releasePayout((string) $leader['user']['id'], (string) $payout['id'], []);
        self::assertTrue((bool) $releaseInit['mfaRequired']);
        $releaseChallenge = $releaseInit['challenge'];
        $released = $this->engine->releasePayout((string) $leader['user']['id'], (string) $payout['id'], [
            'mfaChallengeId' => $releaseChallenge['challengeId'],
            'mfaCode' => $releaseChallenge['demoCode'],
        ]);
        self::assertFalse((bool) $released['mfaRequired']);
        self::assertSame('released', $released['payout']['status']);
        self::assertGreaterThan(0, $released['payout']['netAmount']);
        self::assertGreaterThan(0, $released['payout']['platformFee']);

        $groups = $this->engine->listGroups((string) $leader['user']['id']);
        $fixedGroup = array_values(array_filter($groups, static fn (array $group): bool => $group['id'] === 'grp_fixed_001'))[0];
        self::assertSame(2, $fixedGroup['cycle']);
    }

    public function testComplianceAndAdminLifecycleParity(): void
    {
        $admin = $this->completeLogin('admin@susukonnect.app', 'Admin@2026', 'admin-device');
        $member = $this->completeLogin('member@susukonnect.app', 'Member@2026', 'member-device');

        $overview = $this->engine->adminOverview((string) $admin['user']['id']);
        self::assertNotEmpty($overview['pendingKyc']);

        $reviewed = $this->engine->reviewKyc((string) $admin['user']['id'], 'usr_pending', 'verified');
        self::assertSame('verified', $reviewed['kyc']['status']);

        $flag = $this->engine->createFraudFlag((string) $admin['user']['id'], [
            'targetType' => 'user',
            'targetId' => 'usr_member',
            'reason' => 'Test compliance rule',
        ]);
        self::assertSame('user', $flag['targetType']);

        $dispute = $this->engine->submitDispute((string) $member['user']['id'], 'grp_fixed_001', 'Please review payout order fairness');
        self::assertSame('open', $dispute['status']);

        $resolved = $this->engine->resolveDispute((string) $admin['user']['id'], (string) $dispute['id']);
        self::assertSame('resolved', $resolved['status']);

        $jsonReport = $this->engine->exportReport((string) $admin['user']['id'], 'json');
        self::assertNotEmpty($jsonReport);
        self::assertStringContainsString('generatedAt', $jsonReport);
        $audit = $this->engine->exportAudit((string) $admin['user']['id']);
        self::assertStringContainsString('entries', $audit);
    }

    public function testRoleCapabilityManagementParity(): void
    {
        $leader = $this->completeLogin('leader@susukonnect.app', 'Leader@2026', 'leader-manage');
        $admin = $this->completeLogin('admin@susukonnect.app', 'Admin@2026', 'admin-manage');
        $member = $this->completeLogin('member@susukonnect.app', 'Member@2026', 'member-manage');

        $group = $this->engine->updateGroupConfig((string) $leader['user']['id'], 'grp_fixed_001', [
            'contributionAmount' => 240,
            'gracePeriodDays' => 5,
            'rules' => 'Updated parity rules for cycle management.',
        ]);
        self::assertSame(240.0, (float) $group['contributionAmount']);
        self::assertSame(5, (int) $group['gracePeriodDays']);

        $updatedOrder = $this->engine->updatePayoutOrder((string) $leader['user']['id'], 'grp_fixed_001', ['usr_member', 'usr_leader']);
        self::assertSame(['usr_member', 'usr_leader'], $updatedOrder['payoutOrder']);

        $requested = $this->engine->requestPayout((string) $member['user']['id'], 'grp_vote_001', 'Emergency');
        $reasonReview = $this->engine->reviewPayoutReason((string) $leader['user']['id'], (string) $requested['id'], [
            'decision' => 'approve',
            'note' => 'Leader approved payout reason.',
        ]);
        self::assertSame('approved', $reasonReview['reasonReviewStatus']);

        $archived = $this->engine->moderateGroupChat((string) $leader['user']['id'], 'grp_fixed_001', true);
        self::assertTrue((bool) $archived['chatArchived']);

        $flag = $this->engine->createFraudFlag((string) $admin['user']['id'], [
            'targetType' => 'group',
            'targetId' => 'grp_fixed_001',
            'reason' => 'Parity test compliance check',
        ]);
        self::assertSame('open', $flag['status']);

        $resolved = $this->engine->resolveFraudFlag((string) $admin['user']['id'], (string) $flag['id'], 'Cleared after review');
        self::assertSame('resolved', $resolved['status']);

        $queue = $this->engine->complianceQueue((string) $admin['user']['id']);
        self::assertArrayHasKey('pendingKyc', $queue);
        self::assertArrayHasKey('openFraudFlags', $queue);
    }

    public function testHighTrustOnboardingAndBiometricParity(): void
    {
        $email = 'new.user+' . uniqid('', true) . '@susukonnect.app';
        $password = 'Password123';
        $registration = $this->engine->register([
            'fullName' => 'New User',
            'email' => $email,
            'phone' => '+15551112222',
            'password' => $password,
            'role' => 'member',
            'acceptTerms' => true,
        ]);
        self::assertArrayHasKey('contactVerification', $registration);
        self::assertNotEmpty($registration['contactVerification']['email']['challengeId']);
        self::assertNotEmpty($registration['contactVerification']['phone']['challengeId']);

        try {
            $this->engine->login([
                'email' => $email,
                'password' => $password,
                'deviceId' => 'onboarding-device',
            ]);
            self::fail('Expected contact verification guard to block login.');
        } catch (DomainHttpException $exception) {
            self::assertSame('CONTACT_UNVERIFIED', $exception->errorCode());
        }

        $verifyEmail = $this->engine->verifyOnboardingContact([
            'challengeId' => (string) $registration['contactVerification']['email']['challengeId'],
            'code' => (string) $registration['contactVerification']['email']['demoCode'],
            'channel' => 'email',
        ]);
        self::assertFalse((bool) $verifyEmail['contactsVerified']);

        $resendPhone = $this->engine->resendContactVerification($email, 'phone');
        $verifyPhone = $this->engine->verifyOnboardingContact([
            'challengeId' => (string) $resendPhone['challengeId'],
            'code' => (string) $resendPhone['demoCode'],
            'channel' => 'phone',
        ]);
        self::assertTrue((bool) $verifyPhone['contactsVerified']);

        $login = $this->engine->login([
            'email' => $email,
            'password' => $password,
            'deviceId' => 'onboarding-device',
        ]);
        self::assertTrue((bool) $login['requiresMfa']);

        $verified = $this->engine->verifyLoginMfa([
            'challengeId' => (string) $login['challenge']['challengeId'],
            'code' => (string) $login['challenge']['demoCode'],
            'deviceId' => 'onboarding-device',
        ]);
        self::assertArrayHasKey('tokens', $verified);

        $enrollAttempt = $this->engine->enrollBiometric([
            'email' => $email,
            'password' => $password,
            'deviceId' => 'onboarding-device',
            'deviceLabel' => 'Face ID',
        ]);
        self::assertTrue((bool) $enrollAttempt['mfaRequired']);

        $enrolled = $this->engine->enrollBiometric([
            'email' => $email,
            'password' => $password,
            'deviceId' => 'onboarding-device',
            'deviceLabel' => 'Face ID',
            'mfaChallengeId' => (string) $enrollAttempt['challenge']['challengeId'],
            'mfaCode' => (string) $enrollAttempt['challenge']['demoCode'],
        ]);
        self::assertFalse((bool) $enrolled['mfaRequired']);
        self::assertTrue((bool) $enrolled['user']['biometricEnabled']);
        self::assertTrue((bool) $enrolled['user']['contactsVerified']);

        $biometricLogin = $this->engine->biometricLogin($email, 'onboarding-device');
        self::assertArrayHasKey('tokens', $biometricLogin);
    }

    public function testKycChecksAndAuthenticatorMfaParity(): void
    {
        $email = 'kyc.user+' . uniqid('', true) . '@susukonnect.app';
        $password = 'Password123';
        $registration = $this->engine->register([
            'fullName' => 'Kyc Verified User',
            'email' => $email,
            'phone' => '+15553334444',
            'password' => $password,
            'role' => 'member',
            'acceptTerms' => true,
        ]);

        $this->engine->verifyOnboardingContact([
            'challengeId' => (string) $registration['contactVerification']['email']['challengeId'],
            'code' => (string) $registration['contactVerification']['email']['demoCode'],
            'channel' => 'email',
        ]);
        $this->engine->verifyOnboardingContact([
            'challengeId' => (string) $registration['contactVerification']['phone']['challengeId'],
            'code' => (string) $registration['contactVerification']['phone']['demoCode'],
            'channel' => 'phone',
        ]);

        $login = $this->engine->login([
            'email' => $email,
            'password' => $password,
            'deviceId' => 'kyc-device-1',
        ]);
        self::assertTrue((bool) $login['requiresMfa']);
        self::assertSame('sms', $login['challenge']['method']);

        $verified = $this->engine->verifyLoginMfa([
            'challengeId' => (string) $login['challenge']['challengeId'],
            'code' => (string) $login['challenge']['demoCode'],
            'deviceId' => 'kyc-device-1',
        ]);

        try {
            $this->engine->submitKyc((string) $verified['user']['id'], [
                'idType' => 'passport',
                'idNumber' => 'P1234567',
                'dob' => '07/11/1995',
                'selfieToken' => 'selfie_token',
                'livenessToken' => 'live_123456',
            ]);
            self::fail('Expected invalid DOB to fail KYC.');
        } catch (DomainHttpException $exception) {
            self::assertSame('INVALID_DOB', $exception->errorCode());
        }

        $kyc = $this->engine->submitKyc((string) $verified['user']['id'], [
            'idType' => 'passport',
            'idNumber' => 'P1234567',
            'dob' => '1995-07-11',
            'selfieToken' => 'selfie_token',
            'livenessToken' => 'live_123456',
            'address' => '123 Main Street, Accra',
        ]);
        self::assertSame('pending', $kyc['status']);
        self::assertTrue((bool) $kyc['checks']['livenessVerified']);
        self::assertTrue((bool) $kyc['checks']['nameDobVerified']);

        $securityAttempt = $this->engine->updateSecurity((string) $verified['user']['id'], [
            'mfaEnabled' => true,
            'biometricEnabled' => false,
            'mfaMethod' => 'authenticator',
        ]);
        self::assertTrue((bool) $securityAttempt['mfaRequired']);

        $security = $this->engine->updateSecurity((string) $verified['user']['id'], [
            'mfaEnabled' => true,
            'biometricEnabled' => false,
            'mfaMethod' => 'authenticator',
        ], (string) $securityAttempt['challenge']['challengeId'], (string) $securityAttempt['challenge']['demoCode']);
        self::assertFalse((bool) $security['mfaRequired']);
        self::assertSame('authenticator', $security['user']['mfaMethod']);

        $authLogin = $this->engine->login([
            'email' => $email,
            'password' => $password,
            'deviceId' => 'kyc-device-2',
        ]);
        self::assertTrue((bool) $authLogin['requiresMfa']);
        self::assertSame('authenticator', $authLogin['challenge']['method']);
    }

    public function testAdminCanPurgeSignupAccountsParity(): void
    {
        $admin = $this->completeLogin('admin@susukonnect.app', 'Admin@2026', 'admin-purge-device');
        $email = 'cleanup.user+' . uniqid('', true) . '@susukonnect.app';

        $signup = $this->engine->register([
            'fullName' => 'Cleanup User',
            'email' => $email,
            'phone' => '+15552223333',
            'password' => 'Cleanup123',
            'role' => 'member',
            'acceptTerms' => true,
        ]);
        self::assertNotEmpty($signup['id']);

        $purge = $this->engine->purgeSignupAccounts((string) $admin['user']['id']);
        self::assertGreaterThanOrEqual(1, (int) $purge['deletedCount']);
        self::assertContains((string) $signup['id'], $purge['deletedUserIds']);

        try {
            $this->engine->login([
                'email' => $email,
                'password' => 'Cleanup123',
                'deviceId' => 'cleanup-device',
            ]);
            self::fail('Expected deleted account login to fail.');
        } catch (DomainHttpException $exception) {
            self::assertSame('INVALID_CREDENTIALS', $exception->errorCode());
        }
    }

    /**
     * @return array{tokens:array<string,mixed>,user:array<string,mixed>}
     */
    private function completeLogin(string $email, string $password, string $deviceId): array
    {
        $login = $this->engine->login([
            'email' => $email,
            'password' => $password,
            'deviceId' => $deviceId,
        ]);
        if (($login['requiresMfa'] ?? false) === true) {
            $challenge = $login['challenge'];
            return $this->engine->verifyLoginMfa([
                'challengeId' => (string) $challenge['challengeId'],
                'code' => (string) $challenge['demoCode'],
                'deviceId' => $deviceId,
            ]);
        }

        return [
            'tokens' => $login['tokens'],
            'user' => $login['user'],
        ];
    }
}

final class FakePaymentGateway implements PaymentGatewayInterface
{
    public function chargeContribution(array $payload): array
    {
        return [
            'ok' => true,
            'provider' => $payload['paymentMethodType'] === 'paypal' ? 'paypal' : 'stripe',
            'reference' => 'fake_charge_' . uniqid('', true),
            'raw' => ['mode' => 'test'],
        ];
    }

    public function releasePayout(array $payload): array
    {
        return [
            'ok' => true,
            'provider' => $payload['payoutChannel'] ?? 'stripe',
            'reference' => 'fake_release_' . uniqid('', true),
            'raw' => ['mode' => 'test'],
        ];
    }
}

final class FakeKycProvider implements KycProviderInterface
{
    public function createCase(array $payload): array
    {
        return [
            'provider' => 'stripe_identity',
            'caseId' => 'fake_case_' . $payload['userId'],
            'clientSecret' => 'fake_secret',
            'mode' => 'test',
        ];
    }

    public function verifyIdentity(array $payload): array
    {
        $dob = (string) ($payload['dob'] ?? '');
        $address = trim((string) ($payload['address'] ?? ''));
        return [
            'provider' => 'stripe_identity',
            'referenceId' => 'fake_verify_' . ($payload['userId'] ?? 'user'),
            'mode' => 'test',
            'idDocumentVerified' => strlen((string) ($payload['idNumber'] ?? '')) >= 4,
            'livenessVerified' => strlen((string) ($payload['livenessToken'] ?? '')) >= 6,
            'nameDobVerified' => preg_match('/^\d{4}-\d{2}-\d{2}$/', $dob) === 1,
            'addressVerified' => $address !== '' && strlen($address) >= 8,
        ];
    }
}
