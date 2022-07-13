<?php

declare(strict_types=1);

namespace Inspire\Signer;

use League\Uri\QueryString;
use Psr\Http\Message\UriInterface;
use League\Uri\Http;
use Inspire\Signer\Factories\SignerFactory;

/**
 * Description of BaseSigner
 *
 * @author aalves
 */
abstract class BaseSigner
{

    /**
     * The name of param to set in URL when signing URLs
     *
     * @var string
     */
    protected static string $signParam = 'sign';

    /**
     * The name of expires parameter when signing URL
     *
     * @var string
     */
    protected static string $expiresParameter = 'e';

    /**
     * The name of signature parameter when signing URL
     *
     * @var string
     */
    protected static string $signatureParameter = 's';

    /**
     * The salt for hashing algorithms
     *
     * @var string
     */
    protected string $salt = '';

    /**
     * Signature key to identify validator configuration
     *
     * @var string
     */
    protected string $signatureKey = '';

    /**
     * Extra config
     *
     * @var mixed
     */
    protected ?array $config;

    /**
     * Create a signer object with provided configuration
     *
     * @param string $name
     * @param array $cfg
     * @return BaseSigner
     */
    public static function with(string $name, ?array $cfg = null): BaseSigner
    {
        return SignerFactory::create($name, $cfg);
    }

    /**
     * Sign a input string message
     *
     * @param string $message
     */
    abstract protected function createSignature(string $message): string;

    /**
     *
     * @param array $config
     */
    public function __construct(array $config, string $name)
    {
        $this->config = $config;
        $this->salt = $this->config['key'] ?? '';
        $this->signatureKey = $name;
    }

    /**
     * Section of functions to sign URL
     */

    /**
     * Get a secure URL to a controller action.
     *
     * @param string $url
     * @param \DateTime|int $expiration
     * @throws \Exception
     * @return string
     */
    public function signUrl(string $url, $expiration, ?string $signParam = null): string
    {
        $url = Http::createFromString($url);
        $expiration = $this->getExpirationTimestamp($expiration);
        /**
         * Generate URL signature
         */
        $signature = $this->createSignature("{$url}::{$expiration}::{$this->salt}");

        $query = QueryString::extract($url->getQuery());
        $sign = [
            BaseSigner::$expiresParameter => $expiration,
            BaseSigner::$signatureParameter => $signature,
            'key' => $this->signatureKey
        ];
        $signParam = $signParam ?? BaseSigner::$signParam;
        /**
         * Encode signature and expiration data
         */
        // $query[$signParam] = rtrim(base64_encode($this->buildQueryStringFromArray($sign)), '=');
        $query[$signParam] = rtrim(base64_encode(json_encode($sign)), '=');
        /**
         * Compile URL
         */
        return (string) $url->withQuery($this->buildQueryStringFromArray($query));
    }

    /**
     * Build query string from input array
     *
     * @param array $query
     * @return string
     */
    protected function buildQueryStringFromArray(array $query)
    {
        $buildQuery = [];
        foreach ($query as $key => $value) {
            $buildQuery[] = [
                $key,
                $value
            ];
        }
        return QueryString::build($buildQuery);
    }

    /**
     * Validate a signed url.
     *
     * @param string $url
     * @param string $key
     * @param string $signParam
     * @return boolean
     */
    public static function validateUrl(string $url, ?string $signParam = null)
    {
        BaseSigner::$signParam = $signParam ?? BaseSigner::$signParam;
        $url = Http::createFromString($url);
        $query = QueryString::extract($url->getQuery());
        /**
         * Check if there are all required parameters
         */
        $signParameters = BaseSigner::getSignParameters($query);
        if ($signParameters === null || empty($signParameters)) {
            return false;
        }
        $expiration = $signParameters[BaseSigner::$expiresParameter];
        if (!BaseSigner::isFuture($expiration)) {
            return false;
        }
        $providedSignature = $signParameters[BaseSigner::$signatureParameter];
        /**
         * Create object with correct signer type
         *
         * @var \Psr\Http\Message\UriInterface $intendedUrl
         */
        $signer = BaseSigner::with($signParameters['key']);
        $intendedUrl = $signer->getIntendedUrl($url);
        return $signer->hasValidSignature("{$intendedUrl}::{$expiration}::{$signer->salt}", $providedSignature);
    }

    /**
     * Check if a query is missing a necessary parameter.
     *
     * @param array $query
     * @return bool
     */
    protected static function getSignParameters(array $query): ?array
    {
        if (!isset($query[BaseSigner::$signParam])) {
            return true;
        }
        // $signParameters = QueryString::extract(base64_decode($query[BaseSigner::$signParam]));
        $signParameters = json_decode(base64_decode($query[BaseSigner::$signParam]), true);
        if (json_last_error() != JSON_ERROR_NONE) {
            return null;
        }
        if (!isset($signParameters[BaseSigner::$expiresParameter])) {
            return null;
        }
        if (!isset($signParameters[BaseSigner::$signatureParameter])) {
            return null;
        }
        return $signParameters;
    }

    /**
     * Retrieve the expiration timestamp for a link based on an absolute DateTime or a relative number of days.
     *
     * @param \DateTime|int $expiration
     *            The expiration date of this link.
     *            - DateTime: The value will be used as expiration date
     *            - int: The expiration time will be set to X days from now
     *            
     * @throws \Exception
     *
     * @return string
     */
    protected function getExpirationTimestamp($expiration): string
    {
        if ($expiration instanceof \DateTime) {
            $expiration = $expiration->getTimestamp();
        } else if (is_int($expiration)) {
            if ($expiration < 365) {
                $expiration = (new \DateTime())->modify((int) $expiration . ' days')->getTimestamp();
            }
        } else {
            throw new \Exception('Expiration date must be an instance of DateTime or an integer');
        }
        if (!BaseSigner::isFuture($expiration)) {
            throw new \Exception('Expiration date must be in the future');
        }
        return (string) $expiration;
    }

    /**
     * Retrieve the intended URL by stripping off the UrlSigner specific parameters.
     *
     * @param UriInterface $url
     *
     * @return UriInterface
     */
    protected function getIntendedUrl(UriInterface $url)
    {
        $intendedQuery = QueryString::extract($url->getQuery());
        unset($intendedQuery[BaseSigner::$signParam]);
        return $url->withQuery($this->buildQueryStringFromArray($intendedQuery));
    }

    /**
     * Check if a timestamp is in the future.
     *
     * @param int $timestamp
     *
     * @return bool
     */
    protected static function isFuture($timestamp)
    {
        return ((int) $timestamp) >= time();
    }

    /**
     * Section of functions to sign plain message
     */

    /**
     * Get a secure URL to a controller action.
     *
     * @param string $message
     * @param string $key
     * @return string
     */
    public function sign(string $message): string
    {
        /**
         * Generate message signature
         */
        $signature = $this->createSignature("{$message}::{$this->salt}");
        return base64_encode(http_build_query([
            'sign' => $signature,
            'key' => $this->signatureKey
        ]));
    }

    /**
     * Validate a signed message
     *
     * @param string $url
     * @param string $key
     * @param string $signParam
     * @return boolean
     */
    public static function validate(string $message, string $providedSignature)
    {
        $signature = null;
        parse_str(base64_decode($providedSignature), $signature);
        if (!isset($signature['key'])) {
            throw new \Exception('Signature does not contain a KEY field');
        }
        if (!isset($signature['sign'])) {
            throw new \Exception('Signature does not contain a SIGN field');
        }
        $signer = BaseSigner::with($signature['key']);
        return $signer->hasValidSignature("{$message}::{$signer->salt}", $signature['sign'], null);
    }
}
