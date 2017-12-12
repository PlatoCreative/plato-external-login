<?php

namespace Platocreative\ExternalLogin\Security;

use InvalidArgumentException;

// use Platocreative\ExternalLogin\Security\ExternalLogin;
// use Platocreative\ExternalLogin\Forms\ExternalLoginForm;
// use Platocreative\ExternalLogin\Forms\ExternalLoginCMSMemberLoginForm;
use SilverStripe\Security\Member;
use SilverStripe\Control\Email\Email;
use SilverStripe\Security\Security;
use SilverStripe\Control\Director;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\LoginAttempt;
use SilverStripe\Control\Controller;
use SilverStripe\Forms\Form;
use SilverStripe\Control\Session;
use SilverStripe\Security\LoginForm;
use SilverStripe\Security\MemberAuthenticator\MemberAuthenticator;
use SilverStripe\Core\Environment;

/**
 * Authenticator for "ExternalLogin" method
 *
 * @package external-login
 */
class ExternalMemberAuthenticator extends MemberAuthenticator
{
    /**
     * Attempt to find and authenticate member if possible from the given data
     *
     * @skipUpgrade
     * @param array $data Form submitted data
     * @param ValidationResult $result
     * @param Member $member This third parameter is used in the CMSAuthenticator(s)
     * @return Member Found member, regardless of successful login
     */
    protected function authenticateMember($data, ValidationResult &$result = null, Member $member = null)
    {
        $result = $result ?: ValidationResult::create();

        if (!$member = $this->authenticateExternalMember($data, $result, $member)) {
            return parent::authenticateMember($data, $result, $member);
        }

        return $member;
    }

    /**
     * Attempt to find and authenticate external member if possible from the given data
     *
     * @param array $data Form submitted data
     * @param ValidationResult $result
     * @param Member $member This third parameter is used in the CMSAuthenticator(s)
     * @return Member Found member, regardless of successful login
     */
    protected function authenticateExternalMember($data, ValidationResult &$result = null, Member $member = null)
    {
        $result = $result ?: ValidationResult::create();

        $ssLoginUserName = Environment::getEnv('SS_DEFAULT_ADMIN_USERNAME');

        $email = !empty($data['Email']) ? $data['Email'] : null;

        if ($email != $ssLoginUserName) {
            return;
        }

        // Check for default admin user
        $member = Member::get()->find(
            Member::config()->get('unique_identifier_field'),
            $ssLoginUserName
        );

        if (!$member) {
            return;
        }

        $member->checkLoginPassword($data['Password'], $result);
        return $member;
    }
}
