<?php

declare(strict_types=1);

$seed = random_bytes(SODIUM_CRYPTO_SIGN_SEEDBYTES);
$keypair = sodium_crypto_sign_seed_keypair($seed);
$publicKey = sodium_crypto_sign_publickey($keypair);

fwrite(STDOUT, "seed_hex=" . bin2hex($seed) . PHP_EOL);
fwrite(STDOUT, "public_key_hex=" . bin2hex($publicKey) . PHP_EOL);
