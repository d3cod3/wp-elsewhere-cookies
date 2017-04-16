# wp-elsewhere-cookies

wp-elsewhere-cookies is a WordPress plugin to harden his cookies encryption mechanism.

## Requirements

* PHP >= 5.4
* WordPress >= 4.4 (see https://core.trac.wordpress.org/ticket/33904)

## Installation

Manually copy `libs/` folder and `wp-elsewhere-cookies.php` into your `mu-plugins` folder, [Must Use Plugins](https://codex.wordpress.org/Must_Use_Plugins).

Manually copy `wp-crypto.php` elsewhere, a good choice is copying it outside your server document root and then include it like this:

```php
require_once($_SERVER['DOCUMENT_ROOT'].'/../wp-crypto.php');
```

You'll need to generate your personal encryption key, and add it to `wp-crypto.php`. To do that create a temporary php file like this:

```php
<?php

require_once(__DIR__ . "/libs/php-encryption/CryptoAutoload.php");

echo \Defuse\Crypto\Key::CreateNewRandomKey()->saveToAsciiSafeString();

 ?>
```

Open it in your browser to generate an encryption key, copy-paste it in `wp-crypto.php` and save the file.

## Libraries

This plugin use the following library:

[php-encryption](https://github.com/defuse/php-encryption) To ensure the use of a secure encryption mechanism.
