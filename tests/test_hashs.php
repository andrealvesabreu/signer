<?php
declare(strict_types = 1);
use Inspire\Signer\BaseSigner;
use Inspire\Config\Config;

include dirname(__DIR__) . '/vendor/autoload.php';
$url = 'https://test.com/test/new?a=123&b=456&c=5412&nt=asdf';
Config::loadFromFile('config/signer.php', true);

// Trying MD2
$signed = BaseSigner::with('md2')->signUrl($url, time() + 1);
echo "MD2 SIGNED {$signed}\n";
echo "MD2 SIGNED {$signed} " . (BaseSigner::with('md2')->validateUrl($signed) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n";
sleep(2);
echo "MD2 SIGNED {$signed} " . (BaseSigner::with('md2')->validateUrl($signed) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n\n";

// Trying MD4
$signed = BaseSigner::with('md4')->signUrl($url, time() + 1);
echo "MD4 SIGNED {$signed}\n";
echo "MD4 SIGNED {$signed} " . (BaseSigner::with('md4')->validateUrl($signed) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n";
sleep(2);
echo "MD4 SIGNED {$signed} " . (BaseSigner::with('md4')->validateUrl($signed) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n\n";

// Trying MD5
$signed = BaseSigner::with('md5')->signUrl($url, time() + 1);
echo "MD5 SIGNED {$signed}\n";
echo "MD5 SIGNED {$signed} " . (BaseSigner::with('md5')->validateUrl($signed) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n";
sleep(2);
echo "MD5 SIGNED {$signed} " . (BaseSigner::with('md5')->validateUrl($signed) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n\n";

// Trying SHA1
$signed = BaseSigner::with('sha1')->signUrl($url, time() + 1);
echo "SHA1 SIGNED {$signed}\n";
echo "SHA1 SIGNED {$signed} " . (BaseSigner::with('sha1')->validateUrl($signed) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n";
sleep(2);
echo "SHA1 SIGNED {$signed} " . (BaseSigner::with('sha1')->validateUrl($signed) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n\n";

// Trying SHA256
$signed = BaseSigner::with('sha256')->signUrl($url, time() + 1);
echo "SHA256 SIGNED {$signed}\n";
echo "SHA256 SIGNED {$signed} " . (BaseSigner::with('sha256')->validateUrl($signed) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n";
sleep(2);
echo "SHA256 SIGNED {$signed} " . (BaseSigner::with('sha256')->validateUrl($signed) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n\n";

// Trying SHA384
$signed = BaseSigner::with('sha384')->signUrl($url, time() + 1);
echo "SHA384 SIGNED {$signed}\n";
echo "SHA384 SIGNED {$signed} " . (BaseSigner::with('sha384')->validateUrl($signed) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n";
sleep(2);
echo "SHA384 SIGNED {$signed} " . (BaseSigner::with('sha384')->validateUrl($signed) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n\n";

// Trying SHA512
$signed = BaseSigner::with('sha512')->signUrl($url, time() + 1);
echo "SHA512 SIGNED {$signed}\n";
echo "SHA512 SIGNED {$signed} " . (BaseSigner::with('sha512')->validateUrl($signed) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n";
sleep(2);
echo "SHA512 SIGNED {$signed} " . (BaseSigner::with('sha512')->validateUrl($signed) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n\n";

// Trying HS256
$signed = BaseSigner::with('hs256')->signUrl($url, time() + 1);
echo "HS256 SIGNED {$signed}\n";
echo "HS256 SIGNED {$signed} " . (BaseSigner::with('hs256')->validateUrl($signed) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n";
sleep(2);
echo "HS256 SIGNED {$signed} " . (BaseSigner::with('hs256')->validateUrl($signed) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n\n";

// Trying HS384
$signed = BaseSigner::with('hs384')->signUrl($url, time() + 1);
echo "HS384 SIGNED {$signed}\n";
echo "HS384 SIGNED {$signed} " . (BaseSigner::with('hs384')->validateUrl($signed) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n";
sleep(2);
echo "HS384 SIGNED {$signed} " . (BaseSigner::with('hs384')->validateUrl($signed) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n\n";

// Trying HS512
$signed = BaseSigner::with('hs512')->signUrl($url, time() + 1);
echo "HS512 SIGNED {$signed}\n";
echo "HS512 SIGNED {$signed} " . (BaseSigner::with('hs512')->validateUrl($signed) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n";
sleep(2);
echo "HS512 SIGNED {$signed} " . (BaseSigner::with('hs512')->validateUrl($signed) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n\n";
