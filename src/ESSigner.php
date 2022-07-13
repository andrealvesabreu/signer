<?php

declare(strict_types=1);

namespace Inspire\Signer;

/**
 * Description of ESSigner
 *
 * @author aalves
 */
class ESSigner extends BaseSigner
{

    /**
     *
     * {@inheritdoc}
     * @see \Inspire\Signer\BaseSigner::createSignature()
     */
    protected function createSignature(string $message): string
    {
        if (!isset($this->config['pri_file'])) {
            throw new \Exception("Error. You must provide a private key file.");
        } else if (!file_exists($this->config['pri_file'])) {
            throw new \Exception("Error. The private key file does not exists.");
        }
        $private_key = file_get_contents($this->config['pri_file']);
        $binary_signature = "";
        switch ($this->config['version']) {
                /**
             * Signing with ES256
             */
            case '256':
                openssl_sign($message, $binary_signature, $private_key, OPENSSL_ALGO_SHA256);
                break;
                /**
                 * Signing with ES384
                 */
            case '384':
                openssl_sign($message, $binary_signature, $private_key, OPENSSL_ALGO_SHA384);
                break;
                /**
                 * Signing with ES512
                 */
            case '512':
                openssl_sign($message, $binary_signature, $private_key, OPENSSL_ALGO_SHA512);
                break;
                /**
                 * Invalid algorithm
                 */
            default:
                throw new \Exception("Error. Invalid ES algorithm. {$this->algorithm} is not a valid ES{256,384,512}.");
        }
        return base64_encode($binary_signature);
    }

    /**
     * Check if provided signature is valid
     *
     * @param string $message
     * @param string $providedSignature
     * @return bool
     */
    protected function hasValidSignature(string $message, string $providedSignature): bool
    {
        if (!preg_match('%^[a-zA-Z0-9/+]*={0,2}$%', $providedSignature)) {
            throw new \Exception("Error. Invalid signature format.");
        } else if (!isset($this->config['pub_file'])) {
            throw new \Exception("Error. You must provide a private key file.");
        } else if (!file_exists($this->config['pub_file'])) {
            throw new \Exception("Error. The private key file does not exists.");
        }
        $public_key = file_get_contents($this->config['pub_file']);
        switch ($this->config['version']) {
                /**
             * Checking ES256 signature
             */
            case '256':
                return openssl_verify($message, base64_decode($providedSignature), $public_key, OPENSSL_ALGO_SHA256) == 1;
                /**
                 * Checking ES384 signature
                 */
            case '384':
                return openssl_verify($message, base64_decode($providedSignature), $public_key, OPENSSL_ALGO_SHA384) == 1;
                /**
                 * Checking ES512 signature
                 */
            case '512':
                return openssl_verify($message, base64_decode($providedSignature), $public_key, OPENSSL_ALGO_SHA512) == 1;
                /**
                 * Invalid algorithm
                 */
            default:
                throw new \Exception("Error. Invalid ES algorithm. {$this->algorithm} is not a valid ES{256,384,512}.");
        }
    }
}
