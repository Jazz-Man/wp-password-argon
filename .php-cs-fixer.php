<?php

use JazzMan\PhpCsFixerRules\Config;
use PhpCsFixer\Finder;

$rules_dir = __DIR__.'/vendor/jazzman/php-cs-fixer-rules/src';

require_once $rules_dir.'/Config.php';

$finder = (new Finder())
    ->in(__DIR__)
    ->ignoreDotFiles(true)
    ->ignoreVCS(true)
    ->ignoreVCSIgnored(true)
    ->ignoreUnreadableDirs(true)
    ->files()
    ->name('wp-password-argon.php')
    ->exclude(['vendor', 'php-cs-fixer', 'node_modules', '.idea', '.github', 'cache'])
;

return (new Config())->setFinder($finder);
