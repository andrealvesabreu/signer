<?php
declare(strict_types = 1);
namespace Inspire\Signer;

/**
 * Description of RSSigner
 *
 * @author aalves
 */
class RSSigner extends BaseSigner
{

    /**
     *
     * {@inheritdoc}
     * @see \Inspire\Signer\BaseSigner::createSignature()
     */
    protected function createSignature(string $message): string
    {
        if (! isset($this->config['key'])) {
            throw new \Exception("Error. You must provide a private key file.");
        } else if (! file_exists($this->config['key'])) {
            throw new \Exception("Error. The private key file does not exists.");
        }
        $private_key = file_get_contents($this->config['key']);
        $binary_signature = "";
        switch ($this->algorithm) {
            /**
             * Signing with RS256
             */
            case 'RS256':
                openssl_sign($message, $binary_signature, $private_key, OPENSSL_ALGO_SHA256);
                break;
            /**
             * Signing with RS384
             */
            case 'RS384':
                openssl_sign($message, $binary_signature, $private_key, OPENSSL_ALGO_SHA384);
                break;
            /**
             * Signing with RS512
             */
            case 'RS512':
                openssl_sign($message, $binary_signature, $private_key, OPENSSL_ALGO_SHA512);
                break;
            /**
             * Invalid algorithm
             */
            default:
                throw new \Exception("Error. Invalid RS algorithm. {$this->algorithm} is not a valid RS{256,384,512}.");
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
        if (! isset($this->config['pub'])) {
            throw new \Exception("Error. You must provide a private key file.");
        } else if (! file_exists($this->config['pub'])) {
            throw new \Exception("Error. The private key file does not exists.");
        }
        $public_key = file_get_contents($this->config['pub']);
        switch ($this->algorithm) {
            /**
             * Checking RS256 signature
             */
            case 'RS256':
                return openssl_verify($message, base64_decode($providedSignature), $public_key, OPENSSL_ALGO_SHA256) == 1;
            /**
             * Checking RS384 signature
             */
            case 'RS384':
                return openssl_verify($message, base64_decode($providedSignature), $public_key, OPENSSL_ALGO_SHA384) == 1;
            /**
             * Checking RS512 signature
             */
            case 'RS512':
                return openssl_verify($message, base64_decode($providedSignature), $public_key, OPENSSL_ALGO_SHA512) == 1;
            /**
             * Invalid algorithm
             */
            default:
                throw new \Exception("Error. Invalid RS algorithm. {$this->algorithm} is not a valid RS{256,384,512}.");
        }
    }
}  
    