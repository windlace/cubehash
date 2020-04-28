<?php

declare(strict_types=1);

namespace Cast\Crypto\CubeHash;

function cubehash256($string)
{
    return CubeHash256::hash($string);
}
