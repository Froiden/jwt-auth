<?php

/*
 * This file is part of jwt-auth.
 *
 * (c)Froiden <ajay@froiden.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Froiden\JWTAuth\Contracts\Providers;

interface JWT
{
    /**
     * @param  array  $payload
     * @return string
     */
    public function encode(array $payload);

    /**
     * @param  string  $token
     * @return array
     */
    public function decode($token);
}
