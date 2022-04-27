<?php

/*
 * This file is part of jwt-auth.
 *
 * (c)Froiden <ajay@froiden.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Froiden\JWTAuth\Test\Middleware;

use Illuminate\Http\Request;
use Mockery;
use Froiden\JWTAuth\JWTAuth;
use Froiden\JWTAuth\Test\AbstractTestCase;

abstract class AbstractMiddlewareTest extends AbstractTestCase
{
    /**
     * @var \Mockery\MockInterface|\Froiden\JWTAuth\JWTAuth
     */
    protected $auth;

    /**
     * @var \Mockery\MockInterface|\Illuminate\Http\Request
     */
    protected $request;

    public function setUp(): void
    {
        parent::setUp();

        $this->auth = Mockery::mock(JWTAuth::class);
        $this->request = Mockery::mock(Request::class);
    }
}
