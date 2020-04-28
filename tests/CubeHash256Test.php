<?php

namespace Cast\Crypto\CubeHash\Tests;

use function Cast\Crypto\CubeHash\cubehash256;
use PHPUnit\Framework\TestCase;

class CubeHash256Test extends TestCase
{
    public function test_cubehash256()
    {
        $this->assertEquals('38d1e8a22d7baac6fd5262d83de89cacf784a02caa866335299987722aeabc59', cubehash256(''));
        $this->assertEquals('692638db57760867326f851bd2376533f37b640bd47a0ddc607a9456b692f70f', cubehash256('Hello'));
    }
}
