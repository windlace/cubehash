<?php

namespace Cast\Crypto\CubeHash\Tests;

use Cast\Crypto\CubeHash\CubeHash256;
use function Cast\Crypto\CubeHash\cubehash256;
use PHPUnit\Framework\TestCase;

class CubeHash256Test extends TestCase
{
    public function test_cubehash256()
    {
        $this->assertEquals(
            [
                 -2096419883,    658334063,   -679114902,  1246757400,
                 -1523021469,   -289996037,   1196718146,  1168084361,
                 -2027445816,  -1170162360,   -822837272,   625197683,
                  1543712850,  -1365258909,    759513533,  -424228083,
                -13765010209,  -2824905881,  -9887154026, 19352563566,
                  5669379852, -31581549269,  21359466527, 10648459874,
                 -8561790247,   9779462261, -22434204802, -4124492433,
                 19608647852,   9541915967,   5144979599, -4355863926,
            ],
            CubeHash256::iv(8, 1, 256)
        );
        $this->assertEquals('38d1e8a22d7baac6fd5262d83de89cacf784a02caa866335299987722aeabc59', cubehash256(''));
        $this->assertEquals('692638db57760867326f851bd2376533f37b640bd47a0ddc607a9456b692f70f', cubehash256('Hello'));
    }
}
