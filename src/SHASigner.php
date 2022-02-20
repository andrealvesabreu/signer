<?php
declare(strict_types = 1);
namespace Inspire\Signer;

/**
 * Description of SHASigner
 *
 * @author aalves
 */
class SHASigner extends BaseSigner
{

    /**
     *
     * {@inheritdoc}
     * @see \Inspire\Signer\BaseSigner::createSignature()
     */
    protected function createSignature(string $message): string
    {
        if (empty($this->signatureKey)) {
            throw new \Exception("Error. You must provide a signature key if you are using a signature without certificate.");
        }
        switch ($this->config['version']) {
            /**
             * Hashing with SHA algorithms
             */
            case '1':
            case '256':
            case '384':
            case '512':
                return hash("sha{$this->config['version']}", $message);
            /**
             * Invalid algorithm
             */
            default:
                throw new \Exception("Error. Invalid SHA algorithm. {$this->config['version']} is not a valid SHA.");
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
        $validSignature = $this->createSignature($message);
        return hash_equals($validSignature, $providedSignature);
    }
}  
    