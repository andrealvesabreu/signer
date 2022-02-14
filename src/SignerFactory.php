<?php
declare(strict_types = 1);
namespace Inspire\Signer;

/**
 * Description of SignerFactory
 *
 * @author aalves
 */
final class SignerFactory
{

    private static $signers = [
        'MD2' => 'MD',
        'MD4' => 'MD',
        'MD5' => 'MD',
        'SHA1' => 'SHA',
        'SHA256' => 'SHA',
        'SHA384' => 'SHA',
        'SHA512' => 'SHA',
        'HS256' => 'HS',
        'HS384' => 'HS',
        'HS512' => 'HS',
        'RS256' => 'RS',
        'RS384' => 'RS',
        'RS512' => 'RS',
        'ES256' => 'ES',
        'ES384' => 'ES',
        'ES512' => 'ES',
        'PS256' => 'PS',
        'PS384' => 'PS',
        'PS512' => 'PS'
    ];

    /**
     * Create a signer object based on first argument that say what is the algorithm to use
     *
     * @param string $algorithm
     * @param array $extra
     * @throws \Exception
     * @return BaseSigner|NULL
     */
    public static function create(string $algorithm, ?array $extra = null): ?BaseSigner
    {
        $algFamily = strtoupper($algorithm);
        $className = self::$signers[$algFamily] ?? null;
        $class = "\\Inspire\\Signer\\{$className}Signer";
        if (! class_exists($class)) {
            throw new \Exception("Error. {$class} signer does not exists.");
        }
        return new $class($algorithm, $extra);
    }

    /**
     * Create a signer object based on first argument that say what is the algorithm to use
     *
     * @param mixed ...$args
     * @throws \Exception
     * @return BaseSigner|NULL
     */
    public static function createFromConfig(string $cfg): ?BaseSigner
    {
        $class = '\\Inspire\\Signer\\' . strtoupper($cfg) . 'Signer';
        if (! class_exists($class)) {
            throw new \Exception("Error. {$class} signer does not exists.");
        }
        return new $class($cfg);
    }
}

