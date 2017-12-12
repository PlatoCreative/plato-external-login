<?php

namespace Platocreative\ExternalLogin\Security;

use SilverStripe\Security\Member;
use SilverStripe\Security\Group;
use SilverStripe\Security\Permission;
use SilverStripe\Core\Convert;
use SilverStripe\Core\Environment;
use SilverStripe\ORM\DB;
use SilverStripe\ORM\DataObject;
use SilverStripe\ORM\ValidationResult;

/**
 * Custom Plato Admin User
 *
 * @package external-login
 */
class ExternalLoginMember extends Member
{
    /**
     * DataObject delete permissions
     * @param Member $member
     * @return boolean
     */
    public function canDelete($member = null)
    {
        return false;
    }

    public function checkLoginPassword($password, ValidationResult &$result = null)
    {
        $result = $result ?: ValidationResult::create();

        $ssLoginURL = Environment::getEnv('SS_DEFAULT_ADMIN_EXTERNAL_URL');
        if(!$ssLoginURL){
            $result->addError('SS_DEFAULT_ADMIN_EXTERNAL_URL definition not set.');
            return $result;
        }

        $ssLoginUserName = Environment::getEnv('SS_DEFAULT_ADMIN_USERNAME');

        // Do the api checks
        $curl = curl_init();
        curl_setopt_array($curl, array(
            CURLOPT_RETURNTRANSFER => 1,
            CURLOPT_URL => $ssLoginURL . '?email=' . $ssLoginUserName . '&pwd=' . $password
        ));
        var_dump($curl);
        // Perform the login task
        $request = curl_exec($curl);
        $APIResult = Convert::json2obj($request);

        // Check if login failed and return message
        if(!$APIResult || $APIResult->code > 0 || $APIResult->token == ''){
            $result->addError(_t (
                'Member.ERRORWRONGCRED',
                'The provided details don\'t seem to be correct'
            ));
        }
    }

    /**
     * Set up default default admin record
     */
    public function requireDefaultRecords()
    {
        parent::requireDefaultRecords();

        $ssLoginUserName = Environment::getEnv('SS_DEFAULT_ADMIN_USERNAME');
        if(!$ssLoginUserName){
            return;
        }

        // Check for default admin user by matching email
        $member = Member::get()->find(
            Member::config()->get('unique_identifier_field'),
            $ssLoginUserName
        );

        // If no member is found at this stage.
        // Find member ID 1
        if(!$member){
            $member = DataObject::get_by_id(Member::class, 1);
        }

        $firstName = 'Default Admin';

        // // If there isn't one then make it
        if(!$member){
            $member = ExternalLoginMember::create();
            $member->FirstName = $firstName;
            $member->Email = $ssLoginUserName;
            $member->write();
            DB::alteration_message("Created admin '$member->Email'", 'created');
        } else {
            if ($member->ClassName != $this->ClassName || $member->Email != $ssLoginUserName) {
                $member->ClassName = $this->ClassName;
                $member->FirstName = $firstName;
                $member->Surname = null;
                $member->Email = $ssLoginUserName;
                $member->TempIDHash = null;
                $member->TempIDExpired = null;
                $member->Password = null;
                $member->write();
                DB::alteration_message("Modified admin '$member->Email'", 'modified');
            }
        }

        // Find or create ADMIN group
        Group::singleton()->requireDefaultRecords();
        $adminGroup = Permission::get_groups_by_permission('ADMIN')->First();

        // Ensure this user is in the admin group
        if(!$member->inGroup($adminGroup)) {
            // Add member to group instead of adding group to member
            // This bypasses the privilege escallation code in Member_GroupSet
            $adminGroup->DirectMembers()->add($member);
        }
    }
}
