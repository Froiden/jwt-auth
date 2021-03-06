<?php

/*
 * This file is part of jwt-auth.
 *
 * (c)Froiden <ajay@froiden.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Froiden\JWTAuth\Claims;

class Subject extends Claim
{
    /**
     * {@inheritdoc}
     */
    protected $name = 'sub';
}
