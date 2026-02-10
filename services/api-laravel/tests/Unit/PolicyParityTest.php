<?php

declare(strict_types=1);

namespace Tests\Unit;

use App\Policies\AdminPolicy;
use App\Policies\GroupPolicy;
use PHPUnit\Framework\TestCase;

final class PolicyParityTest extends TestCase
{
    public function testAdminPolicyAllowsOnlyAdmins(): void
    {
        $policy = new AdminPolicy();
        self::assertTrue($policy->admin(['id' => 'usr_admin', 'role' => 'admin']));
        self::assertFalse($policy->admin(['id' => 'usr_member', 'role' => 'member']));
    }

    public function testGroupPolicyAllowsLeaderOrAdmin(): void
    {
        $policy = new GroupPolicy();
        $group = ['leaderId' => 'usr_leader'];

        self::assertTrue($policy->manage(['id' => 'usr_leader', 'role' => 'leader'], $group));
        self::assertTrue($policy->manage(['id' => 'usr_admin', 'role' => 'admin'], $group));
        self::assertFalse($policy->manage(['id' => 'usr_member', 'role' => 'member'], $group));
    }
}
