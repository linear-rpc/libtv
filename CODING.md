# Coding

Please be consist with the [libuv's code style](https://github.com/libuv/libuv/blob/master/CONTRIBUTING.md).
Some differences are below.

 * The functions that are enable to call by any threads should be prefixed with `tv_`
   even if those are internal or non-static functions.
 * The functions that are called by callback thread only should be prefixed with `tv__`.
   Maybe internal or non-static functions.

