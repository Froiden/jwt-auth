<?php

/*
 * This file is part of jwt-auth.
 *
 * (c)Froiden <ajay@froiden.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Froiden\JWTAuth\Validators;

use Froiden\JWTAuth\Claims\Collection;
use Froiden\JWTAuth\Exceptions\TokenInvalidException;

class PayloadValidator extends Validator
{
    /**
     * The required claims.
     *
     * @var array
     */
    protected $requiredClaims = [
        'iss',
        'iat',
        'exp',
        'nbf',
        'sub',
        'jti',
    ];

    /**
     * The refresh TTL.
     *
     * @var int
     */
    protected $refreshTTL = 20160;

    /**
     * Run the validations on the payload array.
     *
     * @param  \Froiden\JWTAuth\Claims\Collection  $value
     * @return \Froiden\JWTAuth\Claims\Collection
     */
    public function check($value)
    {
        $this->validateStructure($value);

        return $this->refreshFlow ? $this->validateRefresh($value) : $this->validatePayload($value);
    }

    /**
     * Ensure the payload contains the required claims and
     * the claims have the relevant type.
     *
     * @param  \Froiden\JWTAuth\Claims\Collection  $claims
     * @return void
     *
     * @throws \Froiden\JWTAuth\Exceptions\TokenInvalidException
     */
    protected function validateStructure(Collection $claims)
    {
        if ($this->requiredClaims && ! $claims->hasAllClaims($this->requiredClaims)) {
            throw new TokenInvalidException('JWT payload does not contain the required claims');
        }
    }

    /**
     * Validate the payload timestamps.
     *
     * @param  \Froiden\JWTAuth\Claims\Collection  $claims
     * @return \Froiden\JWTAuth\Claims\Collection
     *
     * @throws \Froiden\JWTAuth\Exceptions\TokenExpiredException
     * @throws \Froiden\JWTAuth\Exceptions\TokenInvalidException
     */
    protected function validatePayload(Collection $claims)
    {
        return $claims->validate('payload');
    }

    /**
     * Check the token in the refresh flow context.
     *
     * @param  \Froiden\JWTAuth\Claims\Collection  $claims
     * @return \Froiden\JWTAuth\Claims\Collection
     *
     * @throws \Froiden\JWTAuth\Exceptions\TokenExpiredException
     */
    protected function validateRefresh(Collection $claims)
    {
        return $this->refreshTTL === null ? $claims : $claims->validate('refresh', $this->refreshTTL);
    }

    /**
     * Set the required claims.
     *
     * @param  array  $claims
     * @return $this
     */
    public function setRequiredClaims(array $claims)
    {
        $this->requiredClaims = $claims;

        return $this;
    }

    /**
     * Set the refresh ttl.
     *
     * @param  int  $ttl
     * @return $this
     */
    public function setRefreshTTL($ttl)
    {
        $this->refreshTTL = $ttl;

        return $this;
    }
}
