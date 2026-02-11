<?php

namespace AuthxAuth\Tests\Unit;

use AuthxAuth\AdminEmailAllowlist;
use AuthxAuth\Http\Controllers\AuthxAuthController;
use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\After;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

class AuthxAuthControllerEmailVerificationTest extends TestCase
{
    #[After]
    public function clearTestNow(): void
    {
        CarbonImmutable::setTestNow();
    }

    #[Test]
    public function it_uses_email_verified_at_when_present_and_valid(): void
    {
        $controller = new TestableAuthxAuthController(new AdminEmailAllowlist);

        $verifiedAt = $controller->exposedResolveEmailVerifiedAt([
            'email_verified_at' => '2026-02-11T10:15:00Z',
            'email_verified' => false,
        ]);

        $this->assertInstanceOf(CarbonImmutable::class, $verifiedAt);
        $this->assertSame('2026-02-11 10:15:00', $verifiedAt?->utc()->toDateTimeString());
    }

    #[Test]
    public function it_falls_back_to_now_when_email_verified_is_true_and_timestamp_is_missing(): void
    {
        $controller = new TestableAuthxAuthController(new AdminEmailAllowlist);
        CarbonImmutable::setTestNow(CarbonImmutable::parse('2026-02-11T13:30:00Z'));

        $verifiedAt = $controller->exposedResolveEmailVerifiedAt([
            'email_verified' => true,
        ]);

        $this->assertInstanceOf(CarbonImmutable::class, $verifiedAt);
        $this->assertSame('2026-02-11 13:30:00', $verifiedAt?->utc()->toDateTimeString());
    }

    #[Test]
    public function it_returns_null_when_timestamp_is_invalid_and_email_verified_is_not_true(): void
    {
        $controller = new TestableAuthxAuthController(new AdminEmailAllowlist);

        $verifiedAt = $controller->exposedResolveEmailVerifiedAt([
            'email_verified_at' => 'not-a-date',
            'email_verified' => false,
        ]);

        $this->assertNull($verifiedAt);
    }

    #[Test]
    public function it_accepts_truthy_email_verified_strings(): void
    {
        $controller = new TestableAuthxAuthController(new AdminEmailAllowlist);
        CarbonImmutable::setTestNow(CarbonImmutable::parse('2026-02-11T19:00:00Z'));

        $verifiedAt = $controller->exposedResolveEmailVerifiedAt([
            'email_verified' => '1',
        ]);

        $this->assertInstanceOf(CarbonImmutable::class, $verifiedAt);
        $this->assertSame('2026-02-11 19:00:00', $verifiedAt?->utc()->toDateTimeString());
    }
}

class TestableAuthxAuthController extends AuthxAuthController
{
    /**
     * @param  array<string, mixed>  $rawUser
     */
    public function exposedResolveEmailVerifiedAt(array $rawUser): ?CarbonImmutable
    {
        return $this->resolveEmailVerifiedAt($rawUser);
    }
}
