<?php

/*
 * This file is part of jwt-auth.
 *
 * (c)Froiden <ajay@froiden.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Froiden\JWTAuth\Providers;

use Froiden\JWTAuth\Http\Parser\LumenRouteParams;

class LumenServiceProvider extends AbstractServiceProvider
{
    /**
     * {@inheritdoc}
     */
    public function boot()
    {
        $this->app->configure('jwt');

        $path = realpath(__DIR__.'/../../config/config.php');
        $this->mergeConfigFrom($path, 'jwt');

        $this->app->routeMiddleware($this->middlewareAliases);

        $this->extendAuthGuard();

        $this->app['froiden.jwt.parser']->addParser(new LumenRouteParams);
    }
}
