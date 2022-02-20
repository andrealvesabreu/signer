<?php
declare(strict_types = 1);
namespace Inspire\Signer;

/**
 * Description of MDSigner
 *
 * @author aalves
 */
class MDSigner extends BaseSigner
{

    /**
     *
     * {@inheritdoc}
     * @see \Inspire\Signer\BaseSigner::createSignature()
     */
    protected function createSignature(string $message): string
    {
        if (empty($this->config['key'])) {
            throw new \Exception("Error. You must provide a signature key if you are using a signature without certificate.");
        }
        switch ($this->config['version']) {
            /**
             * Hashing with SHA1
             */
            case '2':
            case '4':
            case '5':
                return hash("md{$this->config['version']}", $message);
            /**
             * Invalid algorithm
             */
            default:
                throw new \Exception("Error. Invalid MD algorithm. {$this->algorithm} is not a valid MD{2,4,5}.");
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
    