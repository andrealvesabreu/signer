<?php

declare(strict_types=1);

namespace Inspire\Signer;

/**
 * Description of HSSigner
 *
 * @author aalves
 */
class HSSigner extends BaseSigner
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
             * Hashing with SHA1
             */
            case '256':
            case '384':
            case '512':
                return hash_hmac("sha{$this->config['version']}", $message, $this->signatureKey);
                /**
                 * Invalid algorithm
                 */
            default:
                throw new \Exception("Error. Invalid HS algorithm. {$this->config['version']} is not a valid HS{256,384,512}.");
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
