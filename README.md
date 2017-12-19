# External admin login
Provides external login check for the default admin.

## Requirements
- silverstripe/framework ^3.4

## Installation
Using [Composer](https://getcomposer.org/), insert the following into your command line.
```
composer require plato-creative/plato-external-login ^3.4
```

In the _ss_enviroment.php file add the following:
```
define('SS_LOGIN_URL', 'myadminemail@email.com');
define('SS_LOGIN_EMAIL', 'https://myexternalsitesauthenticator.com');
```

Run `dev/build` to complete the installation process.
