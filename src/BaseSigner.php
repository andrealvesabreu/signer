<?php
declare(strict_types = 1);
namespace Inspire\Signer;

use League\Uri\QueryString;
use Psr\Http\Message\UriInterface;
use League\Uri\Http;
use Spatie\UrlSigner\Exceptions\InvalidExpiration;

/**
 * Description of MD5Signer
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
    private string $signParam = 'sign';

    /**
     * The name of expires parameter when signing URL
     *
     * @var string
     */
    private string $expiresParameter = 'e';

    /**
     * The name of signature parameter when signing URL
     *
     * @var string
     */
    private string $signatureParameter = 's';

    /**
     * The key for hashing algorithms
     *
     * @var string
     */
    protected string $signatureKey = '';

    /**
     * Algorithm to use in signature
     *
     * @var string|NULL
     */
    protected ?string $algorithm = null;

    /**
     * Extra config
     *
     * @var mixed
     */
    protected ?array $config;

    /**
     * Create a signer object with provided configuration
     *
     * @param string $algFamily
     * @param string $algVersion
     * @param mixed $extra
     * @return BaseSigner
     */
    public static function with(string $algorithm, $extra = null): BaseSigner
    {
        return SignerFactory::create($algorithm, $extra);
    }

    /**
     * Create a signer object with provided by file configuration
     *
     * @param string $cfg
     * @return BaseSigner
     */
    public static function withConfig(string $cfg): BaseSigner
    {
        return SignerFactory::createFromConfig($cfg);
    }

    /**
     * Sign a input string message
     *
     * @param string $message
     */
    abstract protected function createSignature(string $message): string;

    /**
     *
     * @param string $algVersion
     * @param mixed $extra
     */
    public function __construct(string $algVersion, $extra)
    {
        $this->algorithm = strtoupper($algVersion);
        $this->config = $extra;
    }

    /**
     * Section of functions to sign URL
     */

    /**
     * Get a secure URL to a controller action.
     *
     * @param string $url
     * @param \DateTime|int $expiration
     * @throws InvalidExpiration
     * @return string
     */
    public function signUrl(string $url, $expiration, ?string $key, ?string $signParam = null): string
    {
        $url = Http::createFromString($url);
        $expiration = $this->getExpirationTimestamp($expiration);
        /**
         * Generate URL signature
         */
        $this->signatureKey = $key ?? $this->signatureKey;
        $signature = $this->createSignature("{$url}::{$expiration}::{$this->signatureKey}");

        $query = QueryString::extract($url->getQuery());
        $sign = [
            $this->expiresParameter => $expiration,
            $this->signatureParameter => $signature
        ];
        $signParam = $signParam ?? $this->signParam;
        /**
         * Encode signature and expiration data
         */
        $query[$signParam] = rtrim(base64_encode($this->buildQueryStringFromArray($sign)), '=');
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
    public function validateUrl(string $url, ?string $key = null, ?string $signParam = null)
    {
        $this->signatureKey = $key ?? $this->signatureKey;
        $this->signParam = $signParam ?? $this->signParam;
        $url = Http::createFromString($url);
        $query = QueryString::extract($url->getQuery());
        /**
         * Check if there are all required parameters
         */
        $signParameters = $this->getSignParameters($query);
        if ($signParameters === null || empty($signParameters)) {
            return false;
        }
        $expiration = $signParameters[$this->expiresParameter];
        if (! $this->isFuture($expiration)) {
            return false;
        }
        $query = QueryString::extract($url->getQuery());
        $providedSignature = $signParameters[$this->signatureParameter];
        $intendedUrl = $this->getIntendedUrl($url);
        return $this->hasValidSignature("{$intendedUrl}::{$expiration}::{$this->signatureKey}", $providedSignature);
    }

    /**
     * Check if a query is missing a necessary parameter.
     *
     * @param array $query
     * @return bool
     */
    protected function getSignParameters(array $query): ?array
    {
        if (! isset($query[$this->signParam])) {
            return true;
        }
        $signParameters = QueryString::extract(base64_decode($query[$this->signParam]));
        if (! isset($signParameters[$this->expiresParameter])) {
            return null;
        }
        if (! isset($signParameters[$this->signatureParameter])) {
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
     * @throws \Spatie\UrlSigner\Exceptions\InvalidExpiration
     *
     * @return string
     */
    protected function getExpirationTimestamp($expiration)
    {
        if (is_int($expiration)) {
            if ($expiration < 365) {
                $expiration = (new \DateTime())->modify((int) $expiration . ' days');
            } else {
                $expiration = (new \DateTime());
            }
        }
        if (! $expiration instanceof \DateTime) {
            throw new InvalidExpiration('Expiration date must be an instance of DateTime or an integer');
        }
        if (! $this->isFuture($expiration->getTimestamp())) {
            throw new InvalidExpiration('Expiration date must be in the future');
        }
        return (string) $expiration->getTimestamp();
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
        unset($intendedQuery[$this->signParam]);
        return $url->withQuery($this->buildQueryStringFromArray($intendedQuery));
    }

    /**
     * Check if a timestamp is in the future.
     *
     * @param int $timestamp
     *
     * @return bool
     */
    protected function isFuture($timestamp)
    {
        return ((int) $timestamp) >= (new \DateTime())->getTimestamp();
    }

    /**
     * Section of functions to sign plain message
     */

    /**
     * Get a secure URL to a controller action.
     *
     * @param string $url
     * @param \DateTime|int $expiration
     * @throws InvalidExpiration
     * @return string
     */
    public function sign(string $message, ?string $key = null): string
    {
        /**
         * Generate message signature
         */
        $this->signatureKey = $key ?? $this->signatureKey;
        return $this->createSignature("{$message}::{$this->signatureKey}");
    }

    /**
     * Validate a signed message
     *
     * @param string $url
     * @param string $key
     * @param string $signParam
     * @return boolean
     */
    public function validate(string $message, string $providedSignature, ?string $key = null)
    {
        $this->signatureKey = $key ?? $this->signatureKey;
        return $this->hasValidSignature("{$message}::{$this->signatureKey}", $providedSignature, null);
    }
}

