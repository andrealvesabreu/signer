<?php

declare(strict_types=1);

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
    private static $signers = ['MD', 'SHA', 'HS', 'RS', 'ES', 'PS'];
    
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
        $algFamily = strtoupper($exists['alg']);
        if (!in_array($algFamily, self::$signers)) {
            throw new \Exception("Error. Algorithm {$algFamily} does not exists.");
        }
        $class = "\\Inspire\\Signer\\{$algFamily}Signer";
        self::$instances[$name] = new $class($exists, $name);
        return self::$instances[$name];
    }
}
