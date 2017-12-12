# External admin login
Provides external login check for the default admin.

## Requirements
- silverstripe/framework ^4.0

## Installation
Using [Composer](https://getcomposer.org/), insert the following into your command line.
```
composer require plato-creative/plato-external-login
```

In the .ENV file add the following:
```
SS_DEFAULT_ADMIN_USERNAME=myadminemail@email.com
SS_DEFAULT_ADMIN_EXTERNAL_URL=https://myexternalsitesauthenticator.com/api/auth/login
```

Run `dev/build` to complete the installation process.
