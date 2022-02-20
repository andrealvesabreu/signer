<?php
declare(strict_types = 1);
namespace Inspire\Signer\Factories;

use Inspire\Config\Config;

/**
 * Description of SignerFactory
 *
 * @author aalves
 */
final class SignerFactory
{

    private static array $instances = [];

    /**
     * Known signer
     *
     * @var array
     */
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
     * @return \Inspire\Signer\BaseSigner|NULL
     */
    public static function create(string $name, ?array $config = null): ?\Inspire\Signer\BaseSigner
    {
        if (isset(self::$instances[$name])) {
            return self::$instances[$name];
        }
        $exists = Config::get("signer.{$name}");
        if ($exists === null) {
            if ($config === null) {
                throw new \Exception("Signer identified by {$name} does not exists.");
            }
            $config = $config ?? [];
            $config['name'] = $name;
            Config::addConfig([
                $config
            ], 'signer', true);
            if (Config::hasErrors()) {
                throw new \Exception("Invalid signer configuration: " . implode(PHP_EOL, Config::getReadableErrors()) . ".");
            }
            $exists = Config::get("signer.{$name}");
        }
        $algFamily = strtoupper($exists['name']);
        $className = self::$signers[$algFamily] ?? null;
        $class = "\\Inspire\\Signer\\{$className}Signer";
        if (! class_exists($class)) {
            throw new \Exception("Error. {$class} signer does not exists.");
        }
        self::$instances[$name] = new $class($exists);
        return self::$instances[$name];
    }
}

