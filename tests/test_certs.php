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

// Trying RS256
$signed = BaseSigner::with('rs256', [
    'alg' => 'rs',
    'version' => 256,
    'pub_file' => __DIR__ . '/certs/rsa_pub.pem',
    'pri_file' => __DIR__ . '/certs/rsa_pri.pem'
])->signUrl($url, time() + 1);
echo "RS256 SIGNED {$signed}\n";
echo "RS256 SIGNED {$signed} " . (BaseSigner::with('rs256')->validateUrl($signed) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n";
sleep(2);
echo "RS256 SIGNED {$signed} " . (BaseSigner::with('rs256')->validateUrl($signed) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n\n";

// Trying RS384
$signed = BaseSigner::with('rs384', [
    'alg' => 'rs',
    'version' => 384,
    'pub_file' => __DIR__ . '/certs/rsa_pub.pem',
    'pri_file' => __DIR__ . '/certs/rsa_pri.pem'
])->signUrl($url, time() + 1);
echo "RS384 SIGNED {$signed}\n";
echo "RS384 SIGNED {$signed} " . (BaseSigner::with('rs384')->validateUrl($signed) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n";
sleep(2);
echo "RS384 SIGNED {$signed} " . (BaseSigner::with('rs384')->validateUrl($signed) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n\n";

// Trying RS512
$signed = BaseSigner::with('rs512', [
    'alg' => 'rs',
    'version' => 512,
    'pub_file' => __DIR__ . '/certs/rsa_pub.pem',
    'pri_file' => __DIR__ . '/certs/rsa_pri.pem'
])->signUrl($url, time() + 1);
echo "RS512 SIGNED {$signed}\n";
echo "RS512 SIGNED {$signed} " . (BaseSigner::with('rs512')->validateUrl($signed) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n";
sleep(2);
echo "RS512 SIGNED {$signed} " . (BaseSigner::with('rs512')->validateUrl($signed) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n\n";

// Trying ES256
$signed = BaseSigner::with('es256', [
    'alg' => 'es',
    'version' => 256,
    'pub_file' => __DIR__ . '/certs/ec_public.pem',
    'pri_file' => __DIR__ . '/certs/ec_private.pem'
])->signUrl($url, time() + 1);
echo "ES256 SIGNED {$signed}\n";
echo "ES256 SIGNED {$signed} " . (BaseSigner::with('es256')->validateUrl($signed) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n";
sleep(2);
echo "ES256 SIGNED {$signed} " . (BaseSigner::with('es256')->validateUrl($signed) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n\n";

// Trying ES384
$signed = BaseSigner::with('es384', [
    'alg' => 'es',
    'version' => 384,
    'pub_file' => __DIR__ . '/certs/ec_public.pem',
    'pri_file' => __DIR__ . '/certs/ec_private.pem'
])->signUrl($url, time() + 1);
echo "ES384 SIGNED {$signed}\n";
echo "ES384 SIGNED {$signed} " . (BaseSigner::with('es384')->validateUrl($signed) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n";
sleep(2);
echo "ES384 SIGNED {$signed} " . (BaseSigner::with('es384')->validateUrl($signed) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n\n";

// Trying ES512
$signed = BaseSigner::with('es512', [
    'alg' => 'es',
    'version' => 512,
    'pub_file' => __DIR__ . '/certs/ec_public.pem',
    'pri_file' => __DIR__ . '/certs/ec_private.pem'
])->signUrl($url, time() + 1);
echo "ES512 SIGNED {$signed}\n";
echo "ES512 SIGNED {$signed} " . (BaseSigner::with('es512')->validateUrl($signed) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n";
sleep(2);
echo "ES512 SIGNED {$signed} " . (BaseSigner::with('es512')->validateUrl($signed) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n\n";

// Trying PS256
$signed = BaseSigner::with('ps256', [
    'alg' => 'ps',
    'version' => 256,
    'pub_file' => __DIR__ . '/certs/rsa_pss_pub.pem',
    'pri_file' => __DIR__ . '/certs/rsa_pss_pri.pem'
])->signUrl($url, time() + 1);
echo "PS256 SIGNED {$signed}\n";
echo "PS256 SIGNED {$signed} " . (BaseSigner::with('ps256')->validateUrl($signed) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n";
sleep(2);
echo "PS256 SIGNED {$signed} " . (BaseSigner::with('ps256')->validateUrl($signed) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n\n";

// Trying PS384
$signed = BaseSigner::with('ps384', [
    'alg' => 'ps',
    'version' => 384,
    'pub_file' => __DIR__ . '/certs/rsa_pss_pub.pem',
    'pri_file' => __DIR__ . '/certs/rsa_pss_pri.pem'
])->signUrl($url, time() + 1);
echo "PS384 SIGNED {$signed}\n";
echo "PS384 SIGNED {$signed} " . (BaseSigner::with('ps384')->validateUrl($signed) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n";
sleep(2);
echo "PS384 SIGNED {$signed} " . (BaseSigner::with('ps384')->validateUrl($signed) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n\n";

// Trying PS512
$signed = BaseSigner::with('ps512', [
    'alg' => 'ps',
    'version' => 512,
    'pub_file' => __DIR__ . '/certs/rsa_pss_pub.pem',
    'pri_file' => __DIR__ . '/certs/rsa_pss_pri.pem'
])->signUrl($url, time() + 1);
echo "PS512 SIGNED {$signed}\n";
echo "PS512 SIGNED {$signed} " . (BaseSigner::with('ps512')->validateUrl($signed) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n";
sleep(2);
echo "PS512 SIGNED {$signed} " . (BaseSigner::with('ps512')->validateUrl($signed) ? "IS VALID" : "ISN'T VALID ANYMORE") . "\n\n";

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














