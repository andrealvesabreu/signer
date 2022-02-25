<?php
declare(strict_types = 1);
use Inspire\Signer\BaseSigner;
use Inspire\Config\Config;

include dirname(__DIR__) . '/vendor/autoload.php';
$message = 'This is a message test for Inspire\signer. It can sign with hash algorithms MD{2,4,5}, SHA{1,256,384,512}, HS{256,384,512} and with cetificates RSA, ECDS and RSAPSSS {256,384,512} algorithms';
Config::loadFromFile('config/signer.php', true);

// Trying MD2
$signature = BaseSigner::with('md2')->sign($message);
echo "MD2 SIGNED {$signature}\n";
echo "MD2 SIGNED {$signature} " . (BaseSigner::validate($message, $signature) ? "IS VALID" : "ISN'T VALID") . "\n";
// Trying MD4
$signature = BaseSigner::with('md4')->sign($message);
echo "MD4 SIGNED {$signature}\n";
echo "MD4 SIGNED {$signature} " . (BaseSigner::validate($message, $signature) ? "IS VALID" : "ISN'T VALID") . "\n";

// Trying MD5
$signature = BaseSigner::with('md5')->sign($message);
echo "MD5 SIGNED {$signature}\n";
echo "MD5 SIGNED {$signature} " . (BaseSigner::validate($message, $signature) ? "IS VALID" : "ISN'T VALID") . "\n";

// Trying SHA1
$signature = BaseSigner::with('sha1')->sign($message);
echo "SHA1 SIGNED {$signature}\n";
echo "SHA1 SIGNED {$signature} " . (BaseSigner::validate($message, $signature) ? "IS VALID" : "ISN'T VALID") . "\n";

// Trying SHA256
$signature = BaseSigner::with('sha256')->sign($message);
echo "SHA256 SIGNED {$signature}\n";
echo "SHA256 SIGNED {$signature} " . (BaseSigner::validate($message, $signature) ? "IS VALID" : "ISN'T VALID") . "\n";

// Trying SHA384
$signature = BaseSigner::with('sha384')->sign($message);
echo "SHA384 SIGNED {$signature}\n";
echo "SHA384 SIGNED {$signature} " . (BaseSigner::validate($message, $signature) ? "IS VALID" : "ISN'T VALID") . "\n";

// Trying SHA512
$signature = BaseSigner::with('sha512')->sign($message);
echo "SHA512 SIGNED {$signature}\n";
echo "SHA512 SIGNED {$signature} " . (BaseSigner::validate($message, $signature) ? "IS VALID" : "ISN'T VALID") . "\n";

// Trying HS256
$signature = BaseSigner::with('hs256')->sign($message);
echo "HS256 SIGNED {$signature}\n";
echo "HS256 SIGNED {$signature} " . (BaseSigner::validate($message, $signature) ? "IS VALID" : "ISN'T VALID") . "\n";

// Trying HS384
$signature = BaseSigner::with('hs384')->sign($message);
echo "HS384 SIGNED {$signature}\n";
echo "HS384 SIGNED {$signature} " . (BaseSigner::validate($message, $signature) ? "IS VALID" : "ISN'T VALID") . "\n";

// Trying HS512
$signature = BaseSigner::with('hs512')->sign($message);
echo "HS512 SIGNED {$signature}\n";
echo "HS512 SIGNED {$signature} " . (BaseSigner::validate($message, $signature) ? "IS VALID" : "ISN'T VALID") . "\n";

// Trying RS256
$signature = BaseSigner::with('rs256')->sign($message);
echo "RS256 SIGNED {$signature}\n";
echo "RS256 SIGNED {$signature} " . (BaseSigner::validate($message, $signature) ? "IS VALID" : "ISN'T VALID") . "\n";

// Trying RS384
$signature = BaseSigner::with('rs384')->sign($message);
echo "RS384 SIGNED {$signature}\n";
echo "RS384 SIGNED {$signature} " . (BaseSigner::validate($message, $signature) ? "IS VALID" : "ISN'T VALID") . "\n";

// Trying RS512
$signature = BaseSigner::with('rs512')->sign($message);
echo "RS512 SIGNED {$signature}\n";
echo "RS512 SIGNED {$signature} " . (BaseSigner::validate($message, $signature) ? "IS VALID" : "ISN'T VALID") . "\n";

// Trying ES256
$signature = BaseSigner::with('es256')->sign($message);
echo "ES256 SIGNED {$signature}\n";
echo "ES256 SIGNED {$signature} " . (BaseSigner::validate($message, $signature) ? "IS VALID" : "ISN'T VALID") . "\n";

// Trying ES384
$signature = BaseSigner::with('es384')->sign($message);
echo "ES384 SIGNED {$signature}\n";
echo "ES384 SIGNED {$signature} " . (BaseSigner::validate($message, $signature) ? "IS VALID" : "ISN'T VALID") . "\n";

// Trying ES512
$signature = BaseSigner::with('es512')->sign($message);
echo "ES512 SIGNED {$signature}\n";
echo "ES512 SIGNED {$signature} " . (BaseSigner::validate($message, $signature) ? "IS VALID" : "ISN'T VALID") . "\n";

// Trying PS256
$signature = BaseSigner::with('ps256')->sign($message);
echo "PS256 SIGNED {$signature}\n";
echo "PS256 SIGNED {$signature} " . (BaseSigner::validate($message, $signature) ? "IS VALID" : "ISN'T VALID") . "\n";

// Trying PS384
$signature = BaseSigner::with('ps384')->sign($message);
echo "PS384 SIGNED {$signature}\n";
echo "PS384 SIGNED {$signature} " . (BaseSigner::validate($message, $signature) ? "IS VALID" : "ISN'T VALID") . "\n";

// Trying PS512
$signature = BaseSigner::with('ps512')->sign($message);
echo "PS512 SIGNED {$signature}\n";
echo "PS512 SIGNED {$signature} " . (BaseSigner::validate($message, $signature) ? "IS VALID" : "ISN'T VALID") . "\n";






