<?php

namespace AuthxAuth\Tests\Fixtures;

use Illuminate\Foundation\Auth\User as Authenticatable;

class RestrictedUser extends Authenticatable
{
    protected $table = 'users';

    /**
     * Mirrors default Laravel User fillable list where email_verified_at is not fillable.
     *
     * @var list<string>
     */
    protected $fillable = [
        'name',
        'email',
        'password',
    ];
}
