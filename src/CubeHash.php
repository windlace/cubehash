<?php

// based on https://github.com/RndPhrase/cubehash.js/blob/master/cubehash.js

namespace Cast\Crypto\CubeHash;

// Cubehash 8/1-256 (CubeHash80+8/1+80-256)
//
// CubeHashi+r/b+f-h
//
// http://cubehash.cr.yp.to
// http://en.wikipedia.org/wiki/CubeHash
//
// example-1: https://github.com/RndPhrase/cubehash.js/blob/master/cubehash.js
// example-2: https://github.com/tearsofphoenix/cubehash/blob/master/index.js

class CubeHash
{   

    /**
     * Init vector computing by 10r rounds as described in the specification.
     *
     * @param   integer $r  The number of rounds per block
     * @param   integer $b  The block size in bytes, defined for {1, 2, 3, ... 128}
     * @param   integer $h  The size of the hash output in bits, defined for {8, 16, 24, 32, ... 512}
     *
     * @return array
     */
    public static function iv($r, $b, $h)
    {
        $initial_state = array_fill(0, 32, 0);
        $initial_state[0] = $h/8;
        $initial_state[1] = $b;
        $initial_state[2] = $r;

        // init state
        $state = new \SplFixedArray(32);

        for ($i = 0; $i < 32; $i += 1) {
            $state[$i] = $initial_state[$i];
        }

        // finalize (10*r)
        for ($i = 0; $i < 10; $i += 1) {
            self::transform($r, $state);
        }

        return $state->toArray();
    }
    
    /**
     * @param string $value Hex
     * @return string
     */
    public static function swapEndianness($value)
    {
        return implode('', array_reverse(str_split($value, 2)));
    }

    /**
     * @param string $value Binary array
     * @return false|string
     */
    public static function swapEndiannessBin($value)
    {
        return hex2bin(self::swapEndianness(bin2hex($value)));
    }

    public static function padBlock($input, $blockSizeBytes)
    {
        $blockSize = $blockSizeBytes * 2;
        $input = bin2hex($input);
//    if (strlen($input) > $blockSize) throw new \InvalidArgumentException("Input data should not be more than {$blockSizeBytes} bytes");
        $input = str_repeat('0', $blockSize - ((strlen($input) % $blockSize) ?: $blockSize)) . $input;
        $input = !strlen($input) ? str_repeat('0', $blockSize) : $input;
        return hex2bin($input);
    }

    /**
     * @param integer $r The number of rounds per block
     * @param integer $b The block size in bytes, defined for {1, 2, 3, ... 128}
     * @param integer $h The size of the hash output in bits, defined for {8, 16, 24, 32, ... 512}
     * @param $data
     * @return string
     */
    public static function hash($r, $b, $h, $data)
    {
        // init state
        $state = new \SplFixedArray(32);

        $iv = self::iv($r, $b, $h);
        
        for ($i = 0; $i < 32; $i += 1) {
            $state[$i] = $iv[$i];
        }

        // update with data
        $data .= hex2bin('80');
        $data = self::swapEndiannessBin($data);
        $data = self::padBlock($data, $b);
        $data = self::swapEndiannessBin($data);

        for ($j = 0; $j < strlen($data); $j += $b) {
            $block = substr($data, $j, $b);
            $block = bin2hex($block);
            $n = 0;
            for ($i = 0; $i < strlen($block); $i += 8) {
                $byte = substr($block, $i, 8);
                $byte = self::swapEndianness($byte);
                $state[$n++] ^= hexdec($byte);
            }
            $state = self::transform($r, $state);
        }

        // finalize
        $state[31] ^= 1;

        for ($i = 0; $i < 10; $i += 1) {
            self::transform($r, $state);
        }

        // Example for '' (empty string hash)
//        $state = [
//              -1561800392 => '38d1e8a2',
//               -961905875 => '2d7baac6',
//               -664644867 => 'fd5262d8',
//              -1399003075 => '3de89cac',
//              -3546249993 => 'f784a02c',
//              -3399252310 => 'aa866335',
//              -2373478103 => '29998772',
//              -2789414358 => '2aeabc59',
//              -1685548184 => '6893889b',
//              -3641377267 => '0dfef426',
//              -1599741972 => 'ecdfa5a0',
//              -3971411240 => 'd8124913',
//              -3644175510 => '6a4bca26',
//              -2826556663 => '092b8657',
//               -854482381 => '33a211cd',
//              -3508776574 => '8251dc2e',
//            -370904486330 => '46ae5ea4',
//            -399992847312 => '308491de',
//            -333955865119 => 'e1e5ad3e',
//            -367735441682 => 'ee764261',
//            -358144429942 => '8ab0ed9c',
//            -372630171200 => 'c0d1823d',
//            -347016896839 => 'b95e2e34',
//            -362137648016 => '7004eaae',
//            -386413349251 => '7d36f807',
//            -350848758866 => 'aecbc84f',
//            -386257376189 => '432c4411',
//            -383406607732 => '8c722fbb',
//            -360378781490 => 'ce30c017',
//            -385614396406 => '0a449737',
//            -401364645913 => 'e787cd8c',
//            -359536410101 => '0bc2f549',
//        ];
        // concat hex produces a hash : 38d1e8a22d7baac6fd5262d83de89cacf784a02caa866335299987722aeabc59

        // convert to hex
        $s = '';
        for ($i = 0; $i < $h/8/4; $i += 1) {
            $s .= self::signed2hex($state[$i], false);
        }

        return $s;
    }

    /**
     * @param   integer         $r      The number of rounds per block
     * @param   \SplFixedArray  $state  The main context
     * @return mixed
     */
    protected static function transform($r, $state)
    {
        $y = new \SplFixedArray(16);

        for ($ri = 0;$ri < $r; $ri += 1) {
            for ($i = 0; $i < 16; $i += 1) $state[$i + 16] += $y[$i^8] = $state[$i];
            for ($i = 0; $i < 16; $i += 1) {

                // *** JS ***
                // a = -2027445816,                                        : 11111111 11111111 11111111 11111111 10000111 00100111 10100001 11001000
                // b = 7                                                   : 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000111
                // JS:  -2027445816 << 7 = -1815026688                     : 11111111 11111111 11111111 11111111 10010011 11010000 11100100 00000000
                // (32 - b) = (32 - 7) = 25                                : 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00011001
                // (a >>> 25) = (-2027445816 >>> 25) = 67                  : 00000000 00000000 00000000 00000000 00000000 00000000 00000000 01000011
                // (a << b) = (-2027445816 << 7) = -1815026688             : 11111111 11111111 11111111 11111111 10010011 11010000 11100100 00000000
                // (a << b) | (a >>> (32 - b)) =
                // = (-2027445816 << 7) | (-2027445816 >>> (32 - 7)) =
                // = (-2027445816 << 7) | (-2027445816 >>> 25) =
                // = -1815026688 | 67 =
                // = -1815026621                                           : 11111111 11111111 11111111 11111111 10010011 11010000 11100100 01000011
                // rotate(y[i],  7) = -1815026621                          : 11111111 11111111 11111111 11111111 10010011 11010000 11100100 01000011
                // state[i + 16] = -15861430220                            : 11111111 11111111 11111111 11111100 01001110 10010101 11001000 00110100
                // rotate(y[i],  7)^state[i + 16] = -582669193             : 11111111 11111111 11111111 11111111 11011101 01000101 00101100 01110111

                // *** PHP ***
                // a = -2027445816                                         : 11111111 11111111 11111111 11111111 10000111 00100111 10100001 11001000
                // b = 7                                                   : 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000111
                // PHP: -2027445816 << 7 = -259513064448                   : 11111111 11111111 11111111 11000011 10010011 11010000 11100100 00000000
                // (32 - b) = (32 - 7) = 25                                : 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00011001
                // (a >>> 25) = (-2027445816 >>> 25) =
                // (a & 0x00000000ffffffff) >> (32 - b) =
                // (-2027445816 & 0x00000000ffffffff) >> 25  = 67          : 00000000 00000000 00000000 00000000 00000000 00000000 00000000 01000011
                // (a << b) = 0xffffffff00000000 | (-2027445816 << 7) =
                // = 0xffffffff00000000 | (-2027445816 << 7) = -1815026688 : 11111111 11111111 11111111 11111111 10010011 11010000 11100100 00000000
                // (0xffffffff00000000 | (a << b)) | ((a & 0x00000000ffffffff) >> (32 - b)) =
                // (0xffffffff00000000 | (-2027445816 << 7)) | ((-2027445816 & 0x00000000ffffffff) >> (32 - 7)) =
                // = -1815026621                                           : 11111111 11111111 11111111 11111111 10010011 11010000 11100100 01000011
                // rotate($y[$i],  7) = -1815026621                        : 11111111 11111111 11111111 11111111 10010011 11010000 11100100 01000011
                // $state[$i + 16] = -15861430220                          : 11111111 11111111 11111111 11111100 01001110 10010101 11001000 00110100
                // rotate($y[$i],  7) ^ $state[$i + 16] =
                // -1815026621 ^ -15861430220 = 16597199991                : 00000000 00000000 00000000 00000011 11011101 01000101 00101100 01110111
                // 0xffffffff00000000 | 16597199991 = -582669193           : 11111111 11111111 11111111 11111111 11011101 01000101 00101100 01110111

                $state[$i]       = i32(self::rotate($y[$i],  7)^$state[$i + 16]);
            }
            for ($i = 0; $i < 16; $i += 1) $y[$i^2]         = $state[$i + 16];
            for ($i = 0; $i < 16; $i += 1) $state[$i + 16]  = $y[$i] + $state[$i];
            for ($i = 0; $i < 16; $i += 1) $y[$i^4]         = $state[$i];
            for ($i = 0; $i < 16; $i += 1) $state[$i]       = i32(self::rotate($y[$i], 11)^$state[$i + 16]);
            for ($i = 0; $i < 16; $i += 2) self::swap($state, $i + 16, $i + 17);
        }

        return $state;
    }

    protected static function rotate($a, $b)
    {
        return (0xffffffff00000000 | ($a << $b)) | (($a & 0x00000000ffffffff) >> (32 - $b));
    }

    protected static function swap($arr, $i, $j)
    {
        $tmp = $arr[$i];
        $arr[$i] = $arr[$j];
        $arr[$j] = $tmp;

        return $arr;
    }

    /**
     * Converts signed decimal to hex (Two's complement)
     *
     * @param $value int, signed
     *
     * @param $reverseEndianness bool, if true reverses the byte order (see machine dependency)
     *
     * @return string, upper case hex value, both bytes padded left with zeros
     */
    protected static function signed2hex($value, $reverseEndianness = true)
    {
        $packed = pack('i', $value);
        $hex='';
        for ($i=0; $i < 4; $i++){
            $hex .= str_pad( dechex(ord($packed[$i])) , 2, '0', STR_PAD_LEFT);
        }
        
        return $reverseEndianness ? self::swapEndianness($hex) : $hex;
    }
}
