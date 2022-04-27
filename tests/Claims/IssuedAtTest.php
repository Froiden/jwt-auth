<?php

/*
 * This file is part of jwt-auth.
 *
 * (c)Froiden <ajay@froiden.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Froiden\JWTAuth\Test\Claims;

use Froiden\JWTAuth\Claims\IssuedAt;
use Froiden\JWTAuth\Exceptions\InvalidClaimException;
use Froiden\JWTAuth\Test\AbstractTestCase;

class IssuedAtTest extends AbstractTestCase
{
    /** @test */
    public function it_should_throw_an_exception_when_passing_a_future_timestamp()
    {
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage('Invalid value provided for claim [iat]');

        new IssuedAt($this->testNowTimestamp + 3600);
    }
}
