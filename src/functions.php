<?php

declare(strict_types=1);

namespace Cast\Crypto\CubeHash;

function cubehash256($r, $b, $string)
{
    return CubeHash256::hash($r, $b, $string);
}

// returns 32-bit representation on 64-bit integer
function i32($value)
{
    $value = ($value & 0xFFFFFFFF);
    if ($value & 0x80000000) $value = -((~$value & 0xFFFFFFFF) + 1);
    return $value;
}
