<?php

declare(strict_types=1);

namespace Inspire\Signer;

use phpseclib3\Crypt\RSA\PrivateKey;
use phpseclib3\Crypt\PublicKeyLoader;

/**
 * Description of PSSigner
 *
 * @author aalves
 */
class PSSigner extends BaseSigner
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
        $private = PrivateKey::load($private_key)->withPadding(PrivateKey::SIGNATURE_PSS);
        switch ($this->config['version']) {
                /**
             * Signing with PS algorithm
             */
            case '256':
            case '384':
            case '512':
                return base64_encode($private->withHash("sha{$this->config['version']}")
                    ->withMGFHash("sha{$this->config['version']}")
                    ->sign($message));
                break;
                /**
                 * Invalid algorithm
                 */
            default:
                throw new \Exception("Error. Invalid PS algorithm. {$this->algorithm} is not a valid PS{256,384,512}.");
        }
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
        $key = PublicKeyLoader::load($public_key)->withPadding(PrivateKey::SIGNATURE_PSS);
        switch ($this->config['version']) {
                /**
             * Checking PS signature
             */
            case '256':
            case '384':
            case '512':
                return $key->withHash("sha{$this->config['version']}")
                    ->withMGFHash("sha{$this->config['version']}")
                    ->verify($message, base64_decode($providedSignature));
                /**
                 * Invalid algorithm
                 */
            default:
                throw new \Exception("Error. Invalid PS algorithm. {$this->algorithm} is not a valid PS{256,384,512}.");
        }
    }
}
