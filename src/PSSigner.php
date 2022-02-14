<?php
declare(strict_types = 1);
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
        if (! isset($this->config['key'])) {
            throw new \Exception("Error. You must provide a private key file.");
        } else if (! file_exists($this->config['key'])) {
            throw new \Exception("Error. The private key file does not exists.");
        }
        $private_key = file_get_contents($this->config['key']);
        $private = PrivateKey::load($private_key)->withPadding(PrivateKey::SIGNATURE_PSS);
        switch ($this->algorithm) {
            /**
             * Signing with PS algorithm
             */
            case 'PS256':
            case 'PS384':
            case 'PS512':
                return base64_encode($private->withHash(str_replace('PS', 'sha', $this->algorithm))
                    ->withMGFHash(str_replace('PS', 'sha', $this->algorithm))
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
        if (! isset($this->config['pub'])) {
            throw new \Exception("Error. You must provide a private key file.");
        } else if (! file_exists($this->config['pub'])) {
            throw new \Exception("Error. The private key file does not exists.");
        }
        $public_key = file_get_contents($this->config['pub']);
        $key = PublicKeyLoader::load($public_key)->withPadding(PrivateKey::SIGNATURE_PSS);
        switch ($this->algorithm) {
            /**
             * Checking PS signature
             */
            case 'PS256':
            case 'PS384':
            case 'PS512':
                return $key->withHash(str_replace('PS', 'sha', $this->algorithm))
                    ->withMGFHash(str_replace('PS', 'sha', $this->algorithm))
                    ->verify($message, base64_decode($providedSignature));
            /**
             * Invalid algorithm
             */
            default:
                throw new \Exception("Error. Invalid PS algorithm. {$this->algorithm} is not a valid PS{256,384,512}.");
        }
    }
}  
    