<?php

namespace Cast\Crypto\CubeHash\Tests;

use Cast\Crypto\CubeHash\CubeHash;
use function Cast\Crypto\CubeHash\cubehash256;
use function Cast\Crypto\CubeHash\cubehash512;
use PHPUnit\Framework\TestCase;

class CubeHashTest extends TestCase
{
    public function test_cubehash256()
    {
        // CubeHash10+1/1+10-256:
        $this->assertEquals(
            [
                 -1364746004,   1413475564,   -896460311,  1495629273,
                   831721974,  -1114895892,  -1131802667, -1345622233,
                  -966112469,  -1678886309,   -691894012,  1358586066,
                 -1854453552,  -1070683759,    748270806,  1529972269,
                  2136745624,   4462657195,   9868789035,  6357691622,
                 -4981802178,  -6422354290,  -1400617557, -2741214963,
                  -272471494,   5329758627,   2868717903,   710720199,
                  -709654222,   2807896093,   2249717683,  2710321235,
            ],
            CubeHash::iv(1, 1, 256)
        );
        $this->assertEquals('80f72e07d04ddadb44a78823e0af2ea9f72ef3bf366fd773aa1fa33fc030e5cb', cubehash256(1, 1, ''));
        $this->assertEquals('f63041a946aa98bd47f3175e6009dcb2ccf597b2718617ba46d56f27ffe35d49', cubehash256(1, 1, 'Hello'));
        $this->assertEquals('217a4876f2b24cec489c9171f85d53395cc979156ea0254938c4c2c59dfdf8a4', cubehash256(1, 1, 'The quick brown fox jumps over the lazy dog'));

        // CubeHash80+8/1+80-256
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
            CubeHash::iv(8, 1, 256)
        );
        $this->assertEquals('38d1e8a22d7baac6fd5262d83de89cacf784a02caa866335299987722aeabc59', cubehash256(8, 1, ''));
        $this->assertEquals('692638db57760867326f851bd2376533f37b640bd47a0ddc607a9456b692f70f', cubehash256(8, 1, 'Hello'));
        $this->assertEquals('94e0c958d85cdfaf554919980f0f50b945b88ad08413e0762d6ff0219aff3e55', cubehash256(8, 1, 'The quick brown fox jumps over the lazy dog'));

        // CubeHash160+16/32+160-256
        $this->assertEquals(
            [
                  -366226252,   -858328417,   1662090865,    893918894,
                   575745371,   -438743453,   2120368433,   -187952450,
                 -1026509162,   1118773360,   -797832139,    862050956,
                   684518564,  -1896305277,   1182837760,   1088813995,
                  7928299971,   5922880469, -36834009791, -21731580295,
                -42794932919,  35964212739,  -2587323651, -57649962363,
                  5015516590, -27409035680, -45243252771,  58068387621,
                -29703972117,   5548452566, -40318076753, -30769206262,
            ],
            CubeHash::iv(16, 32, 256)
        );
        $this->assertEquals('44c6de3ac6c73c391bf0906cb7482600ec06b216c7c54a2a8688a6a42676577d', cubehash256(16, 32, ''));
        $this->assertEquals('e712139e3b892f2f5fe52d0f30d78a0cb16b51b217da0e4acb103dd0856f2db0', cubehash256(16, 32, 'Hello'));
        $this->assertEquals('5151e251e348cbbfee46538651c06b138b10eeb71cf6ea6054d7ca5fec82eb79', cubehash256(16, 32, 'The quick brown fox jumps over the lazy dog'));
    }

    public function test_cubehash512()
    {
        // CubeHash80+8/1+80-512
        $this->assertEquals(
            [
                  1771631453,    -83283769,   1620347152,  -433711601,
                   906460403,  -1249178356,   1473190205,   859957176,
                 -1556840357,    545913327,    838845460,   720320592,
                   -32368583,   -381639598,   2102563746,  1883621906,
                -10412881554,   6471774260, -10291731382,  2479046363,
                 -8241550972,   9840352208,  24633482738,  5671924652,
                 18969519388, -28488698309,  16604957416, 29977988879,
                 16460907259,  -9979419578,  -4139768411, -3730686628,
            ],
            CubeHash::iv(8, 1, 512)
        );
        $this->assertEquals(
            '90bc3f2948f7374065a811f1e47a208a53b1a2f3be1c0072759ed49c9c6c7f28f26eb30d5b0658c563077d599da23f97df0c2c0ac6cce734ffe87b2e76ff7294',
            cubehash512(8, 1, '')
        );
        $this->assertEquals(
            '7ce309a25e2e1603ca0fc369267b4d43f0b1b744ac45d6213ca08e75675664448e2f62fdbf7bbd637ce40fc293286d75b9d09e8dda31bd029113e02ecccfd39b',
            cubehash512(8, 1, 'Hello')
        );
        $this->assertEquals(
            'ca942b088ed9103726af1fa87b4deb59e50cf3b5c6dcfbcebf5bba22fb39a6be9936c87bfdd7c52fc5e71700993958fa4e7b5e6e2a3672122475c40f9ec816ba',
            cubehash512(8, 1, 'The quick brown fox jumps over the lazy dog')
        );


        // CubeHash160+16/32+160-512
        $this->assertEquals(
            [
                   719989345,   1358206164,   760449931,  1097324606,
                  1072571155,   -956182644,  -868641138,  1353471637,
                  1296222087,  -1505253197, -1748038673, -2107947721,
                  -285711150,   -232746812,  -790246093, -1573318226,
                 30011529433,  17524843653, 47697722351, -5532007118,
                -75525562023,  22279452700, -1845855948,  8820285097,
                 16481290795,  -1515778443, -5607381930, -5427862154,
                -25348159241, -34769167631, 14891209286, 20740717380,
            ],
            CubeHash::iv(16, 32, 512)
        );
        $this->assertEquals(
            '4a1d00bbcfcb5a9562fb981e7f7db3350fe2658639d948b9d57452c22328bb32f468b072208450bad5ee178271408be0b16e5633ac8a1e3cf9864cfbfc8e043a',
            cubehash512(16, 32, '')
        );
        $this->assertEquals(
            'dcc0503aae279a3c8c95fa1181d37c418783204e2e3048a081392fd61bace883a1f7c4c96b16b4060c42104f1ce45a622f1a9abaeb994beb107fed53a78f588c',
            cubehash512(16, 32, 'Hello')
        );
        $this->assertEquals(
            'bdba44a28cd16b774bdf3c9511def1a2baf39d4ef98b92c27cf5e37beb8990b7cdb6575dae1a548330780810618b8a5c351c1368904db7ebdf8857d596083a86',
            cubehash512(16, 32, 'The quick brown fox jumps over the lazy dog')
        );
    }
}
