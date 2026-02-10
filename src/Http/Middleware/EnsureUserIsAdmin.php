<?php

namespace AuthxAuth\Http\Middleware;

use AuthxAuth\AdminEmailAllowlist;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;

class EnsureUserIsAdmin
{
    public function __construct(
        protected AdminEmailAllowlist $adminEmailAllowlist,
    ) {}

    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $userEmail = $request->user()?->email;

        if (! $this->adminEmailAllowlist->allows($userEmail)) {
            Auth::guard('web')->logout();
            $request->session()->invalidate();
            $request->session()->regenerateToken();

            abort(403, 'Only admin users can access this application.');
        }

        return $next($request);
    }
}
