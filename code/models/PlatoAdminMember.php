<?php
/*
*   Custom Plato Admin User
*/
use GuzzleHttp\Psr7;
class PlatoAdminMember extends Member {
    private static $db = array();

    public function canDelete($member = null) {
        return false;
    }

    public function canEdit($member = null) {
        if(!$member || !(is_a($member, 'Member')) || is_numeric($member)){
            $member = Member::currentUser();
        }
        // extended access checks
        $results = $this->extend('canEdit', $member);
        if($results) {
            return $results;
        } else {
            return false;
        }
    }

    public function checkPlatoAdminPassword($email, $password) {
        $result = $this->canLogIn();

        // Check URL has been defined
        if(defined('SS_LOGIN_URL')){
            // Short-circuit the result upon failure, no further checks needed.
            if(!$result->valid()){
                return $result;
            }

            // Do the api checks
            $baseURL = SS_LOGIN_URL . '/api/auth/login';
            $curl = curl_init();
            curl_setopt_array($curl, array(
                CURLOPT_RETURNTRANSFER => 1,
                CURLOPT_URL => $baseURL . '?email=' . $email . '&pwd=' . $password
            ));

            // Perfom the login task
            $request = curl_exec($curl);
            $APIResult = Convert::json2obj($request);

            // Check if login failed and return message
            if(!$APIResult || $APIResult->code > 0 || $APIResult->token == ''){
                $result->error(_t (
                    'Member.ERRORWRONGCRED',
                    'The provided details don\'t seem to be correct. Please try again.'
                ));
            } else {
                // Log the user out
                $logoutURL = SS_LOGIN_URL . '/api/auth/logout';
                $curl = curl_init();
                curl_setopt_array($curl, array(
                    CURLOPT_RETURNTRANSFER => 1,
                    CURLOPT_URL => $logoutURL . '?email=' . $email
                ));
            }
        }

        return $result;
    }
}
