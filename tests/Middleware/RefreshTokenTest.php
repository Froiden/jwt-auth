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

use Illuminate\Http\Response;
use Mockery;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;
use Froiden\JWTAuth\Exceptions\TokenInvalidException;
use Froiden\JWTAuth\Http\Middleware\RefreshToken;
use Froiden\JWTAuth\Http\Parser\Parser;

class RefreshTokenTest extends AbstractMiddlewareTest
{
    /**
     * @var \Froiden\JWTAuth\Http\Middleware\RefreshToken
     */
    protected $middleware;

    public function setUp(): void
    {
        parent::setUp();

        $this->middleware = new RefreshToken($this->auth);
    }

    /** @test */
    public function it_should_refresh_a_token()
    {
        $parser = Mockery::mock(Parser::class);
        $parser->shouldReceive('hasToken')->once()->andReturn(true);

        $this->auth->shouldReceive('parser')->andReturn($parser);

        $this->auth->parser()->shouldReceive('setRequest')->once()->with($this->request)->andReturn($this->auth->parser());
        $this->auth->shouldReceive('parseToken->refresh')->once()->andReturn('foo.bar.baz');

        $response = $this->middleware->handle($this->request, function () {
            return new Response;
        });

        $this->assertSame($response->headers->get('authorization'), 'Bearer foo.bar.baz');
    }

    /** @test */
    public function it_should_throw_an_unauthorized_exception_if_token_not_provided()
    {
        $this->expectException(UnauthorizedHttpException::class);

        $parser = Mockery::mock(Parser::class);
        $parser->shouldReceive('hasToken')->once()->andReturn(false);

        $this->auth->shouldReceive('parser')->andReturn($parser);
        $this->auth->parser()->shouldReceive('setRequest')->once()->with($this->request)->andReturn($this->auth->parser());

        $this->middleware->handle($this->request, function () {
            //
        });
    }

    /** @test */
    public function it_should_throw_an_unauthorized_exception_if_token_invalid()
    {
        $this->expectException(UnauthorizedHttpException::class);

        $parser = Mockery::mock(Parser::class);
        $parser->shouldReceive('hasToken')->once()->andReturn(true);

        $this->auth->shouldReceive('parser')->andReturn($parser);

        $this->auth->parser()->shouldReceive('setRequest')->once()->with($this->request)->andReturn($this->auth->parser());
        $this->auth->shouldReceive('parseToken->refresh')->once()->andThrow(new TokenInvalidException);

        $this->middleware->handle($this->request, function () {
            //
        });
    }
}