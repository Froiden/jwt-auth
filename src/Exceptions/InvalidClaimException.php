<?php

/*
 * This file is part of jwt-auth.
 *
 * (c)Froiden <ajay@froiden.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Froiden\JWTAuth\Exceptions;

use Exception;
use Froiden\JWTAuth\Claims\Claim;

class InvalidClaimException extends JWTException
{
    /**
     * Constructor.
     *
     * @param  \Froiden\JWTAuth\Claims\Claim  $claim
     * @param  int  $code
     * @param  \Exception|null  $previous
     * @return void
     */
    public function __construct(Claim $claim, $code = 0, Exception $previous = null)
    {
        parent::__construct('Invalid value provided for claim ['.$claim->getName().']', $code, $previous);
    }
}
