<?php

/*
 * This file is part of jwt-auth.
 *
 * (c)Froiden <ajay@froiden.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Froiden\JWTAuth\Http\Parser;

use Illuminate\Http\Request;
use Froiden\JWTAuth\Contracts\Http\Parser as ParserContract;

class InputSource implements ParserContract
{
    use KeyTrait;

    /**
     * Try to parse the token from the request input source.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return null|string
     */
    public function parse(Request $request)
    {
        return $request->input($this->key);
    }
}
