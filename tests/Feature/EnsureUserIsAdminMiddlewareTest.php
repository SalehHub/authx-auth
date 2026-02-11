<?php

namespace AuthxAuth\Tests\Feature;

use AuthxAuth\Tests\Fixtures\User;
use AuthxAuth\Tests\TestCase;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\Test;

class EnsureUserIsAdminMiddlewareTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        Route::middleware(['web', 'auth', 'admin'])
            ->get('/admin-area', fn () => response('ok', 200));
    }

    #[Test]
    public function it_allows_admin_emails(): void
    {
        config()->set('authx-auth.admin_emails', ['admin@example.com']);

        $user = User::query()->create([
            'name' => 'Admin',
            'email' => 'admin@example.com',
        ]);

        $response = $this->actingAs($user)->get('/admin-area');

        $response->assertOk();
    }

    #[Test]
    public function it_blocks_non_admin_emails_and_logs_out(): void
    {
        config()->set('authx-auth.admin_emails', ['admin@example.com']);

        $user = User::query()->create([
            'name' => 'Non Admin',
            'email' => 'user@example.com',
        ]);

        $response = $this->actingAs($user)->get('/admin-area');

        $response->assertForbidden();
        $this->assertGuest();
    }
}
