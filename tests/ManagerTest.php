<?php

/*
 * This file is part of jwt-auth.
 *
 * (c)Froiden <ajay@froiden.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Froiden\JWTAuth\Test;

use Mockery;
use Froiden\JWTAuth\Blacklist;
use Froiden\JWTAuth\Claims\Collection;
use Froiden\JWTAuth\Claims\Expiration;
use Froiden\JWTAuth\Claims\IssuedAt;
use Froiden\JWTAuth\Claims\Issuer;
use Froiden\JWTAuth\Claims\JwtId;
use Froiden\JWTAuth\Claims\NotBefore;
use Froiden\JWTAuth\Claims\Subject;
use Froiden\JWTAuth\Contracts\Providers\JWT;
use Froiden\JWTAuth\Exceptions\JWTException;
use Froiden\JWTAuth\Exceptions\TokenBlacklistedException;
use Froiden\JWTAuth\Factory;
use Froiden\JWTAuth\Manager;
use Froiden\JWTAuth\Payload;
use Froiden\JWTAuth\Token;
use Froiden\JWTAuth\Validators\PayloadValidator;

class ManagerTest extends AbstractTestCase
{
    /**
     * @var \Mockery\MockInterface|\Froiden\JWTAuth\Contracts\Providers\JWT
     */
    protected $jwt;

    /**
     * @var \Mockery\MockInterface|\Froiden\JWTAuth\Blacklist
     */
    protected $blacklist;

    /**
     * @var \Mockery\MockInterface|\Froiden\JWTAuth\Factory
     */
    protected $factory;

    /**
     * @var \Froiden\JWTAuth\Manager
     */
    protected $manager;

    /**
     * @var \Mockery\MockInterface
     */
    protected $validator;

    public function setUp(): void
    {
        parent::setUp();

        $this->jwt = Mockery::mock(JWT::class);
        $this->blacklist = Mockery::mock(Blacklist::class);
        $this->factory = Mockery::mock(Factory::class);
        $this->manager = new Manager($this->jwt, $this->blacklist, $this->factory);
        $this->validator = Mockery::mock(PayloadValidator::class);
    }

    /** @test */
    public function it_should_encode_a_payload()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp + 3600),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp),
            new JwtId('foo'),
        ];

        $collection = Collection::make($claims);

        $this->validator->shouldReceive('setRefreshFlow->check')->andReturn($collection);
        $payload = new Payload($collection, $this->validator);

        $this->jwt->shouldReceive('encode')->with($payload->toArray())->andReturn('foo.bar.baz');

        $token = $this->manager->encode($payload);

        $this->assertEquals($token, 'foo.bar.baz');
    }

    /** @test */
    public function it_should_decode_a_token()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp + 3600),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp),
            new JwtId('foo'),
        ];
        $collection = Collection::make($claims);

        $this->validator->shouldReceive('setRefreshFlow->check')->andReturn($collection);
        $payload = new Payload($collection, $this->validator);

        $token = new Token('foo.bar.baz');

        $this->jwt->shouldReceive('decode')->once()->with('foo.bar.baz')->andReturn($payload->toArray());

        $this->factory->shouldReceive('setRefreshFlow')->andReturn($this->factory);
        $this->factory->shouldReceive('customClaims')->andReturn($this->factory);
        $this->factory->shouldReceive('make')->andReturn($payload);

        $this->blacklist->shouldReceive('has')->with($payload)->andReturn(false);

        $payload = $this->manager->decode($token);

        $this->assertInstanceOf(Payload::class, $payload);
        $this->assertSame($payload->count(), 6);
    }

    /** @test */
    public function it_should_throw_exception_when_token_is_blacklisted()
    {
        $this->expectException(TokenBlacklistedException::class);
        $this->expectExceptionMessage('The token has been blacklisted');

        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp + 3600),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp),
            new JwtId('foo'),
        ];
        $collection = Collection::make($claims);

        $this->validator->shouldReceive('setRefreshFlow->check')->andReturn($collection);
        $payload = new Payload($collection, $this->validator);
        $token = new Token('foo.bar.baz');

        $this->jwt->shouldReceive('decode')->once()->with('foo.bar.baz')->andReturn($payload->toArray());

        $this->factory->shouldReceive('setRefreshFlow')->andReturn($this->factory);
        $this->factory->shouldReceive('customClaims')->with($payload->toArray())->andReturn($this->factory);
        $this->factory->shouldReceive('make')->andReturn($payload);

        $this->blacklist->shouldReceive('has')->with($payload)->andReturn(true);

        $this->manager->decode($token);
    }

    /** @test */
    public function it_should_refresh_a_token()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp - 3600),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp),
            new JwtId('foo'),
        ];
        $collection = Collection::make($claims);

        $this->validator->shouldReceive('setRefreshFlow->check')->andReturn($collection);
        $payload = new Payload($collection, $this->validator);
        $token = new Token('foo.bar.baz');

        $this->jwt->shouldReceive('decode')->twice()->with('foo.bar.baz')->andReturn($payload->toArray());
        $this->jwt->shouldReceive('encode')->with($payload->toArray())->andReturn('baz.bar.foo');

        $this->factory->shouldReceive('setRefreshFlow')->with(true)->andReturn($this->factory);
        $this->factory->shouldReceive('customClaims')->andReturn($this->factory);
        $this->factory->shouldReceive('make')->andReturn($payload);

        $this->blacklist->shouldReceive('has')->with($payload)->andReturn(false);
        $this->blacklist->shouldReceive('add')->once()->with($payload);

        $token = $this->manager->refresh($token);

        // $this->assertArrayHasKey('ref', $payload);
        $this->assertInstanceOf(Token::class, $token);
        $this->assertEquals('baz.bar.foo', $token);
    }

    /** @test */
    public function it_should_invalidate_a_token()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp + 3600),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp),
            new JwtId('foo'),
        ];
        $collection = Collection::make($claims);

        $this->validator->shouldReceive('setRefreshFlow->check')->andReturn($collection);
        $payload = new Payload($collection, $this->validator);
        $token = new Token('foo.bar.baz');

        $this->jwt->shouldReceive('decode')->once()->with('foo.bar.baz')->andReturn($payload->toArray());

        $this->factory->shouldReceive('setRefreshFlow')->andReturn($this->factory);
        $this->factory->shouldReceive('customClaims')->with($payload->toArray())->andReturn($this->factory);
        $this->factory->shouldReceive('make')->andReturn($payload);

        $this->blacklist->shouldReceive('has')->with($payload)->andReturn(false);

        $this->blacklist->shouldReceive('add')->with($payload)->andReturn(true);

        $this->manager->invalidate($token);
    }

    /** @test */
    public function it_should_force_invalidate_a_token_forever()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp + 3600),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp),
            new JwtId('foo'),
        ];
        $collection = Collection::make($claims);

        $this->validator->shouldReceive('setRefreshFlow->check')->andReturn($collection);
        $payload = new Payload($collection, $this->validator);
        $token = new Token('foo.bar.baz');

        $this->jwt->shouldReceive('decode')->once()->with('foo.bar.baz')->andReturn($payload->toArray());

        $this->factory->shouldReceive('setRefreshFlow')->andReturn($this->factory);
        $this->factory->shouldReceive('customClaims')->with($payload->toArray())->andReturn($this->factory);
        $this->factory->shouldReceive('make')->andReturn($payload);

        $this->blacklist->shouldReceive('has')->with($payload)->andReturn(false);

        $this->blacklist->shouldReceive('addForever')->with($payload)->andReturn(true);

        $this->manager->invalidate($token, true);
    }

    /** @test */
    public function it_should_throw_an_exception_when_enable_blacklist_is_set_to_false()
    {
        $this->expectException(JWTException::class);
        $this->expectExceptionMessage('You must have the blacklist enabled to invalidate a token.');

        $token = new Token('foo.bar.baz');

        $this->manager->setBlacklistEnabled(false)->invalidate($token);
    }

    /** @test */
    public function it_should_get_the_payload_factory()
    {
        $this->assertInstanceOf(Factory::class, $this->manager->getPayloadFactory());
    }

    /** @test */
    public function it_should_get_the_jwt_provider()
    {
        $this->assertInstanceOf(JWT::class, $this->manager->getJWTProvider());
    }

    /** @test */
    public function it_should_get_the_blacklist()
    {
        $this->assertInstanceOf(Blacklist::class, $this->manager->getBlacklist());
    }
}
