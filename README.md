CubeHash
---
**Pure PHP-implementation without any extensions**

#### Install:
```php
composer require cast/cubehash
```

#### Usage:
```php
<?php

use function Cast\Crypto\CubeHash\cubehash256;

cubehash256('Hello'); // 8/1-256
// 692638db57760867326f851bd2376533f37b640bd47a0ddc607a9456b692f70f

```

Based on https://github.com/RndPhrase/cubehash.js/blob/master/cubehash.js.
