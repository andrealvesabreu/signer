<?php
declare(strict_types = 1);
use Inspire\Signer\BaseSigner;

include dirname(__DIR__) . '/vendor/autoload.php';
$message = 'This is a message test for Inspire\signer. It can sign with hash algorithms MD{2,4,5}, SHA{1,256,384,512}, HS{256,384,512} and with cetificates RSA, ECDS and RSAPSSS {256,384,512} algorithms';
$pass = 'fkasldkjghajlkshgd';

// Trying MD2
$signature = BaseSigner::with('md2')->sign($message, $pass);
echo "MD2 SIGNED {$signature}\n";
echo "MD2 SIGNED {$signature} " . (BaseSigner::with('md2')->validate($message, $signature, $pass) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n";

// Trying MD4
$signature = BaseSigner::with('md4')->sign($message, $pass);
echo "MD4 SIGNED {$signature}\n";
echo "MD4 SIGNED {$signature} " . (BaseSigner::with('md4')->validate($message, $signature, $pass) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n";
exit();
// Trying MD5
$signature = BaseSigner::with('md5')->sign($message, $pass);
echo "MD5 SIGNED {$signature}\n";
echo "MD5 SIGNED {$signature} " . (BaseSigner::with('md5')->validate($message, $signature, $pass) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n";

// Trying SHA1
$signature = BaseSigner::with('sha1')->sign($message, $pass);
echo "SHA1 SIGNED {$signature}\n";
echo "SHA1 SIGNED {$signature} " . (BaseSigner::with('sha1')->validate($message, $signature, $pass) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n";

// Trying SHA256
$signature = BaseSigner::with('sha256')->sign($message, $pass);
echo "SHA256 SIGNED {$signature}\n";
echo "SHA256 SIGNED {$signature} " . (BaseSigner::with('sha256')->validate($message, $signature, $pass) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n";

// Trying SHA384
$signature = BaseSigner::with('sha384')->sign($message, $pass);
echo "SHA384 SIGNED {$signature}\n";
echo "SHA384 SIGNED {$signature} " . (BaseSigner::with('sha384')->validate($message, $signature, $pass) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n";

// Trying SHA512
$signature = BaseSigner::with('sha512')->sign($message, $pass);
echo "SHA512 SIGNED {$signature}\n";
echo "SHA512 SIGNED {$signature} " . (BaseSigner::with('sha512')->validate($message, $signature, $pass) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n";

// Trying HS256
$signature = BaseSigner::with('hs256')->sign($message, $pass);
echo "HS256 SIGNED {$signature}\n";
echo "HS256 SIGNED {$signature} " . (BaseSigner::with('hs256')->validate($message, $signature, $pass) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n";

// Trying HS384
$signature = BaseSigner::with('hs384')->sign($message, $pass);
echo "HS384 SIGNED {$signature}\n";
echo "HS384 SIGNED {$signature} " . (BaseSigner::with('hs384')->validate($message, $signature, $pass) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n";

// Trying HS512
$signature = BaseSigner::with('hs512')->sign($message, $pass);
echo "HS512 SIGNED {$signature}\n";
echo "HS512 SIGNED {$signature} " . (BaseSigner::with('hs512')->validate($message, $signature, $pass) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n";

// Trying RS256
$signature = BaseSigner::with('rs256', [
    'key' => __DIR__ . '/certs/key.pem'
])->sign($message, $pass);
echo "RS256 SIGNED {$signature}\n";
echo "RS256 SIGNED {$signature} " . (BaseSigner::with('rs256', [
    'pub' => __DIR__ . '/certs/cert.pem'
])->validate($message, $signature, $pass) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n";

// Trying RS384
$signature = BaseSigner::with('rs384', [
    'key' => __DIR__ . '/certs/key.pem'
])->sign($message, $pass);
echo "RS384 SIGNED {$signature}\n";
echo "RS384 SIGNED {$signature} " . (BaseSigner::with('rs384', [
    'pub' => __DIR__ . '/certs/cert.pem'
])->validate($message, $signature, $pass) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n";

// Trying RS512
$signature = BaseSigner::with('rs512', [
    'key' => __DIR__ . '/certs/key.pem'
])->sign($message, $pass);
echo "RS512 SIGNED {$signature}\n";
echo "RS512 SIGNED {$signature} " . (BaseSigner::with('rs512', [
    'pub' => __DIR__ . '/certs/cert.pem'
])->validate($message, $signature, $pass) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n";

// Trying ES256
$signature = BaseSigner::with('es256', [
    'key' => __DIR__ . '/certs/ec_private.pem'
])->sign($message, $pass);
echo "ES256 SIGNED {$signature}\n";
echo "ES256 SIGNED {$signature} " . (BaseSigner::with('es256', [
    'pub' => __DIR__ . '/certs/ec_public.pem'
])->validate($message, $signature, $pass) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n";

// Trying ES384
$signature = BaseSigner::with('es384', [
    'key' => __DIR__ . '/certs/ec_private.pem'
])->sign($message, $pass);
echo "ES384 SIGNED {$signature}\n";
echo "ES384 SIGNED {$signature} " . (BaseSigner::with('es384', [
    'pub' => __DIR__ . '/certs/ec_public.pem'
])->validate($message, $signature, $pass) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n";

// Trying ES512
$signature = BaseSigner::with('es512', [
    'key' => __DIR__ . '/certs/ec_private.pem'
])->sign($message, $pass);
echo "ES512 SIGNED {$signature}\n";
echo "ES512 SIGNED {$signature} " . (BaseSigner::with('es512', [
    'pub' => __DIR__ . '/certs/ec_public.pem'
])->validate($message, $signature, $pass) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n";

// Trying PS256
$signature = BaseSigner::with('ps256', [
    'key' => __DIR__ . '/certs/rsa_pss_pri.pem'
])->sign($message, $pass);
echo "PS256 SIGNED {$signature}\n";
echo "PS256 SIGNED {$signature} " . (BaseSigner::with('ps256', [
    'pub' => __DIR__ . '/certs/rsa_pss_pub.pem'
])->validate($message, $signature, $pass) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n";

// Trying PS384
$signature = BaseSigner::with('ps384', [
    'key' => __DIR__ . '/certs/rsa_pss_pri.pem'
])->sign($message, $pass);
echo "PS384 SIGNED {$signature}\n";
echo "PS384 SIGNED {$signature} " . (BaseSigner::with('ps384', [
    'pub' => __DIR__ . '/certs/rsa_pss_pub.pem'
])->validate($message, $signature, $pass) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n";

// Trying PS512
$signature = BaseSigner::with('ps512', [
    'key' => __DIR__ . '/certs/rsa_pss_pri.pem'
])->sign($message, $pass);
echo "PS512 SIGNED {$signature}\n";
echo "PS512 SIGNED {$signature} " . (BaseSigner::with('ps512', [
    'pub' => __DIR__ . '/certs/rsa_pss_pub.pem'
])->validate($message, $signature, $pass) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n";

