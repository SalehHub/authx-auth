<?php

namespace AuthxAuth\Tests\Unit;

use AuthxAuth\AdminEmailAllowlist;
use AuthxAuth\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

class AdminEmailAllowlistTest extends TestCase
{
    #[Test]
    public function it_normalizes_emails_from_config(): void
    {
        config()->set('authx-auth.admin_emails', [' ADMIN@Example.com ', 'owner@example.com', 1, '']);

        $allowlist = new AdminEmailAllowlist;

        $this->assertSame(['admin@example.com', 'owner@example.com'], $allowlist->emails());
        $this->assertTrue($allowlist->allows('ADMIN@example.com'));
    }

    #[Test]
    public function it_returns_empty_list_for_invalid_config_type(): void
    {
        config()->set('authx-auth.admin_emails', 'admin@example.com');

        $allowlist = new AdminEmailAllowlist;

        $this->assertSame([], $allowlist->emails());
        $this->assertFalse($allowlist->allows(null));
        $this->assertFalse($allowlist->allows(''));
    }
}
