<?php
declare(strict_types = 1);
namespace Inspire\Signer;

use League\Uri\QueryString;
use Psr\Http\Message\UriInterface;
use League\Uri\Http;
use Inspire\Signer\Factories\SignerFactory;

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
     * @param array $config
     */
    public function __construct(array $config)
    {
        $this->config = $config;
        $this->signatureKey = $this->config['key'] ?? '';
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
    public function validateUrl(string $url, ?string $signParam = null)
    {
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
        if (! $this->isFuture($expiration)) {
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
    public function validate(string $message, string $providedSignature)
    {
        return $this->hasValidSignature("{$message}::{$this->signatureKey}", $providedSignature, null);
    }
}

