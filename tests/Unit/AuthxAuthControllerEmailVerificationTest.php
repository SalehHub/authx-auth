<?php

namespace AuthxAuth\Tests\Unit;

use AuthxAuth\AdminEmailAllowlist;
use AuthxAuth\AuthxAuthConfig;
use AuthxAuth\Http\Controllers\AuthxAuthController;
use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
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
        $controller = new TestableAuthxAuthController(new AdminEmailAllowlist(new AuthxAuthConfig), new AuthxAuthConfig);

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
        $controller = new TestableAuthxAuthController(new AdminEmailAllowlist(new AuthxAuthConfig), new AuthxAuthConfig);
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
        $controller = new TestableAuthxAuthController(new AdminEmailAllowlist(new AuthxAuthConfig), new AuthxAuthConfig);

        $verifiedAt = $controller->exposedResolveEmailVerifiedAt([
            'email_verified_at' => 'not-a-date',
            'email_verified' => false,
        ]);

        $this->assertNull($verifiedAt);
    }

    #[Test]
    public function it_accepts_truthy_email_verified_strings(): void
    {
        $controller = new TestableAuthxAuthController(new AdminEmailAllowlist(new AuthxAuthConfig), new AuthxAuthConfig);
        CarbonImmutable::setTestNow(CarbonImmutable::parse('2026-02-11T19:00:00Z'));

        $verifiedAt = $controller->exposedResolveEmailVerifiedAt([
            'email_verified' => '1',
        ]);

        $this->assertInstanceOf(CarbonImmutable::class, $verifiedAt);
        $this->assertSame('2026-02-11 19:00:00', $verifiedAt?->utc()->toDateTimeString());
    }

    #[Test]
    public function it_prefers_auth_provider_from_payload(): void
    {
        $controller = new TestableAuthxAuthController(new AdminEmailAllowlist(new AuthxAuthConfig), new AuthxAuthConfig);

        $provider = $controller->exposedResolveAuthProvider([
            'auth_provider' => 'GOOGLE',
        ]);

        $this->assertSame('google', $provider);
    }

    #[Test]
    public function it_inferrs_google_auth_provider_from_google_id(): void
    {
        $controller = new TestableAuthxAuthController(new AdminEmailAllowlist(new AuthxAuthConfig), new AuthxAuthConfig);

        $provider = $controller->exposedResolveAuthProvider([
            'google_id' => 'google-55',
        ]);

        $this->assertSame('google', $provider);
    }

    #[Test]
    public function it_inferrs_google_auth_provider_from_existing_user_google_id(): void
    {
        $controller = new TestableAuthxAuthController(new AdminEmailAllowlist(new AuthxAuthConfig), new AuthxAuthConfig);
        $existingUser = new UserWithAttributes;
        $existingUser->setAttribute('google_id', 'google-77');

        $provider = $controller->exposedResolveAuthProvider([], $existingUser);

        $this->assertSame('google', $provider);
    }

    #[Test]
    public function it_defaults_auth_provider_to_authx(): void
    {
        $controller = new TestableAuthxAuthController(new AdminEmailAllowlist(new AuthxAuthConfig), new AuthxAuthConfig);

        $provider = $controller->exposedResolveAuthProvider([]);

        $this->assertSame('authx', $provider);
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

    /**
     * @param  array<string, mixed>  $rawUser
     */
    public function exposedResolveAuthProvider(array $rawUser, ?Model $existingUser = null): string
    {
        return $this->resolveAuthProvider($rawUser, $existingUser);
    }
}

class UserWithAttributes extends Model
{
    protected $guarded = [];
}
