<?php
declare(strict_types = 1);
use Inspire\Signer\BaseSigner;

/**
 * Generate certs
 */

/**
 * Generate RSA key pair
 * openssl req -x509 -newkey rsa:2048 -keyout rsa_pri.pem -out rsa_pub.pem -days 10950 -nodes -subj "/CN=unused"
 *
 * Generate RSA-PSS key pair
 * openssl req -x509 -newkey rsa:2048 -keyout rsa_pss_pri.pem -sigopt rsa_padding_mode:pss -sha1 -sigopt rsa_pss_saltlen:20 -out rsa_pss_pub.pem -days 10950 -nodes -subj "/CN=unused"
 *
 * Generate ECDSA key pair
 * openssl ecparam -genkey -name prime256v1 -noout -out ec_private.pem
 * openssl ec -in ecdsa_pri.pem -pubout -out ecdsa_pub.pem
 */

include dirname(__DIR__) . '/vendor/autoload.php';
$url = 'https://test.com/test/new?a=123&b=456&c=5412&nt=asdf';
$pass = 'fkasldkjghajlkshgd';

// Trying RS256
$signed = BaseSigner::with('rs256', [
    'key' => __DIR__ . '/certs/key.pem'
])->signUrl($url, time() + 2, $pass);
echo "RS256 SIGNED {$signed}\n";
echo "RS256 SIGNED {$signed} " . (BaseSigner::with('rs256', [
    'pub' => __DIR__ . '/certs/cert.pem'
])->validateUrl($signed, $pass) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n";
sleep(2);
echo "RS256 SIGNED {$signed} " . (BaseSigner::with('rs256', [
    'pub' => __DIR__ . '/certs/cert.pem'
])->validateUrl($signed, $pass) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n\n";

// Trying RS384
$signed = BaseSigner::with('rs384', [
    'key' => __DIR__ . '/certs/key.pem'
])->signUrl($url, time() + 2, $pass);
echo "RS384 SIGNED {$signed}\n";
echo "RS384 SIGNED {$signed} " . (BaseSigner::with('rs384', [
    'pub' => __DIR__ . '/certs/cert.pem'
])->validateUrl($signed, $pass) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n";
sleep(2);
echo "RS384 SIGNED {$signed} " . (BaseSigner::with('rs384', [
    'pub' => __DIR__ . '/certs/cert.pem'
])->validateUrl($signed, $pass) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n\n";

// Trying RS512
$signed = BaseSigner::with('rs512', [
    'key' => __DIR__ . '/certs/key.pem'
])->signUrl($url, time() + 2, $pass);
echo "RS512 SIGNED {$signed}\n";
echo "RS512 SIGNED {$signed} " . (BaseSigner::with('rs512', [
    'pub' => __DIR__ . '/certs/cert.pem'
])->validateUrl($signed, $pass) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n";
sleep(2);
echo "RS512 SIGNED {$signed} " . (BaseSigner::with('rs512', [
    'pub' => __DIR__ . '/certs/cert.pem'
])->validateUrl($signed, $pass) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n\n";

// Trying ES256
$signed = BaseSigner::with('es256', [
    'key' => __DIR__ . '/certs/ec_private.pem'
])->signUrl($url, time() + 2, $pass);
echo "ES256 SIGNED {$signed}\n";
echo "ES256 SIGNED {$signed} " . (BaseSigner::with('es256', [
    'pub' => __DIR__ . '/certs/ec_public.pem'
])->validateUrl($signed, $pass) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n";
sleep(2);
echo "ES256 SIGNED {$signed} " . (BaseSigner::with('es256', [
    'pub' => __DIR__ . '/certs/ec_public.pem'
])->validateUrl($signed, $pass) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n\n";

// Trying ES384
$signed = BaseSigner::with('es384', [
    'key' => __DIR__ . '/certs/ec_private.pem'
])->signUrl($url, time() + 2, $pass);
echo "ES384 SIGNED {$signed}\n";
echo "ES384 SIGNED {$signed} " . (BaseSigner::with('es384', [
    'pub' => __DIR__ . '/certs/ec_public.pem'
])->validateUrl($signed, $pass) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n";
sleep(2);
echo "ES384 SIGNED {$signed} " . (BaseSigner::with('es384', [
    'pub' => __DIR__ . '/certs/ec_public.pem'
])->validateUrl($signed, $pass) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n\n";

// Trying ES512
$signed = BaseSigner::with('es512', [
    'key' => __DIR__ . '/certs/ec_private.pem'
])->signUrl($url, time() + 2, $pass);
echo "ES512 SIGNED {$signed}\n";
echo "ES512 SIGNED {$signed} " . (BaseSigner::with('es512', [
    'pub' => __DIR__ . '/certs/ec_public.pem'
])->validateUrl($signed, $pass) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n";
sleep(2);
echo "ES512 SIGNED {$signed} " . (BaseSigner::with('es512', [
    'pub' => __DIR__ . '/certs/ec_public.pem'
])->validateUrl($signed, $pass) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n\n";

// Trying PS256
$signed = BaseSigner::with('ps256', [
    'key' => __DIR__ . '/certs/rsa_pss_pri.pem'
])->signUrl($url, time() + 2, $pass);
echo "PS256 SIGNED {$signed}\n";
echo "PS256 SIGNED {$signed} " . (BaseSigner::with('ps256', [
    'pub' => __DIR__ . '/certs/rsa_pss_pub.pem'
])->validateUrl($signed, $pass) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n";
sleep(2);
echo "PS256 SIGNED {$signed} " . (BaseSigner::with('ps256', [
    'pub' => __DIR__ . '/certs/rsa_pss_pub.pem'
])->validateUrl($signed, $pass) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n\n";

// Trying PS384
$signed = BaseSigner::with('ps384', [
    'key' => __DIR__ . '/certs/rsa_pss_pri.pem'
])->signUrl($url, time() + 2, $pass);
echo "PS384 SIGNED {$signed}\n";
echo "PS384 SIGNED {$signed} " . (BaseSigner::with('ps384', [
    'pub' => __DIR__ . '/certs/rsa_pss_pub.pem'
])->validateUrl($signed, $pass) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n";
sleep(2);
echo "PS384 SIGNED {$signed} " . (BaseSigner::with('ps384', [
    'pub' => __DIR__ . '/certs/rsa_pss_pub.pem'
])->validateUrl($signed, $pass) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n\n";

// Trying PS512
$signed = BaseSigner::with('ps512', [
    'key' => __DIR__ . '/certs/rsa_pss_pri.pem'
])->signUrl($url, time() + 2, $pass);
echo "PS512 SIGNED {$signed}\n";
echo "PS512 SIGNED {$signed} " . (BaseSigner::with('ps512', [
    'pub' => __DIR__ . '/certs/rsa_pss_pub.pem'
])->validateUrl($signed, $pass) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n";
sleep(2);
echo "PS512 SIGNED {$signed} " . (BaseSigner::with('ps512', [
    'pub' => __DIR__ . '/certs/rsa_pss_pub.pem'
])->validateUrl($signed, $pass) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n\n";

/**
 * Generate RSA key pair
 * openssl req -x509 -newkey rsa:2048 -keyout rsa_pri.pem -out rsa_pub.pem -days 10950 -nodes -subj "/CN=unused"
 * 
 * Generate RSA-PSS key pair
 * openssl req -x509 -newkey rsa:2048 -keyout rsa_pss_pri.pem -sigopt rsa_padding_mode:pss -sha1 -sigopt rsa_pss_saltlen:20 -out rsa_pss_pub.pem -days 10950 -nodes -subj "/CN=unused"
 * 
 * Generate ECDSA key pair
 * openssl ecparam -genkey -name prime256v1 -noout -out ec_private.pem
 * openssl ec -in ecdsa_pri.pem -pubout -out ecdsa_pub.pem
 */














