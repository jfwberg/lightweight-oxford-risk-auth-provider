/**
 * @author         Justus van den Berg (jfwberg@gmail.com)
 * @date           October 2025
 * @copyright      (c) 2025 Justus van den Berg
 * @license        MIT (See LICENSE file in the project root)
 * @description    Class for testing the OxfordRiskAuthProvider Methods
 */
@IsTest
private with sharing class OxfordRiskAuthProviderTest {

    /** **************************************************************************************************** **
     **                                      PRIVATE TEST DATA VARIABLE                                      **
     ** **************************************************************************************************** **/
    // Variables for holding test data
    private static OxfordRiskAuthProvider authProvider;
    private static Map<String,String> authProviderConfig;

    // Method and overload methods to create a new User
    private static User runAsUser; 


    /** **************************************************************************************************** **
     **                                         TEST SUPPORT METHODS                                         **
     ** **************************************************************************************************** **/
    /**
     * @description Method to create a run as user with a profile and permission set
     *              to separate setup DML
     * @return      The run as user with the correct profile
     */
    private static User getRunAsUser(){
        if(runAsUser == null){
            System.runAs(utl.Tst.getRunningUser()){
                runAsUser = utl.Tst.createRunAsUser(
                    utl.Tst.MINIMUM_ACCESS_PROFILE,
                    'Lightweight_Oxford_Risk_Auth_Provider'
                );
            }
        }
        return runAsUser;
    }


    /** **************************************************************************************************** **
     **                                             TEST METHODS                                             **
     ** **************************************************************************************************** **/
    /**
     * @description Method to test the initiate function
     */
    @IsTest
    static void testInitiate(){

        PageReference pageReference;

        // Test the method
        Test.startTest();
        System.runAs(getRunAsUser()){
            pageReference = getAuthProvider().initiate(getAuthProviderConfig(),'TestState');
        }
        Test.stopTest();

        // Assert test results
        Assert.areEqual(
            pageReference.getUrl(),
            URL.getOrgDomainUrl().toExternalForm() + '/services/authcallback/TestAuthProvider?state=TestState',
            'Unexpected callback URL'
        );
    }


    /**
     * @description Method to test the handleCallback() function
     */
    @IsTest
    static void testHandleCallback(){

        // Assertion variables
        Auth.AuthProviderTokenResponse tokenResponse;

        // Setup the response from the callable action
        utl.Clbl.setActionResponse('updateMappingLoginDetails', null);
        utl.Clbl.setActionResponse('checkUserMappingExists',    true);
        utl.Clbl.setActionResponse('getSubjectFromUserMapping', 'federationId');
        utl.Clbl.setActionResponse('insertLoginHistoryRecord',  null);


        // Setup the mock response
        utl.Mck.setResponse(200, JSON.serializePretty(new Map<String,String>{
            'access_token' => 'access_token_value',
            'token_type'   => 'Bearer',
            'expires_in'   => '1682439225'
        }));

        // Test the method
        Test.startTest();
        System.runAs(getRunAsUser()){
            tokenResponse = getTokenResponse();
        }
        Test.stopTest();

        // Assert test results
        Assert.areEqual('access_token_value', tokenResponse.oauthToken, 'Unexpected oauthToken value');
        Assert.areEqual('TestState',          tokenResponse.state     , 'Unexpected state value');
    }


    /**
     * @description Method to test the refresh() function
     */
    @IsTest
    static void testRefresh(){

        // Assertion variables
        Auth.OAuthRefreshResult refreshResult;

        // Setup the callable
        utl.Clbl.setActionResponse('insertLoginHistoryRecord',  null);

        // Setup the mock response
        utl.Mck.setResponse(200, JSON.serializePretty(new Map<String,String>{
            'access_token' => 'access_token_value',
            'token_type'   => 'Bearer',
            'expires_in'   => '1682439225'
        }));

        // Test the method
        Test.startTest();
        System.runAs(getRunAsUser()){
            refreshResult = getAuthProvider().refresh(getAuthProviderConfig(),'[REFRESH_TOKEN]');
        }
        Test.stopTest();

        // Assert test results
        Assert.areEqual('access_token_value',    refreshResult.accessToken, 'Unexpected accessToken value');
    }


    /**
     * @description Method to test the getUserInfo() function
     */
    @IsTest
    static void testGetUserInfo(){

        // Assertion variables
        Auth.UserData userData;

        // Setup the callable
        utl.Clbl.setActionResponse('insertLoginHistoryRecord',  null);

        // Setup the mock response
        utl.Mck.setResponse(200, JSON.serializePretty(new Map<String,String>{
            'access_token' => 'access_token_value',
            'token_type'   => 'Bearer',
            'expires_in'   => '1682439225'
        }));

        // Test the method
        Test.startTest();
        System.runAs(getRunAsUser()){
            userData = getAuthProvider().getUserInfo(
                getAuthProviderConfig(),
                getTokenResponse()
            );
        }
        Test.stopTest();

        // Assert test results
        Assert.areEqual(runAsUser.Email,    userData.email, 'Unexpected email value');
    }


    /**
     * @description Method to test the getCustomMetadataType() function
     */
    @IsTest
    static void testGetCustomMetadataType(){
        System.runAs(getRunAsUser()){
            Assert.areEqual(
                String.valueOf(OxfordRiskAuthProvider__mdt.getSObjectType()),
                getAuthProvider().getCustomMetadataType(),
                'Unexpected custom metadata value'
            );
        }
    }


    /**
     * @description Method to test the exceptions thrown in case there is no package installed
     */
    @IsTest
    @SuppressWarnings('PMD.ApexUnitTestClassShouldHaveAsserts')
    static void testHandleException(){

        // Run once so it is initialized
        getAuthProviderConfig();

        // Override the user config and enable error logging to "test" the callable methods
        authProviderConfig.put(OxfordRiskAuthProvider.ENABLE_ERROR_LOGGING_FIELD_NAME, 'true');

        // Setup the response from the callable action
        utl.Clbl.setActionResponse('insertLog', null);

        try{
            OxfordRiskAuthProvider orap = new OxfordRiskAuthProvider();

            System.runAs(getRunAsUser()){
                // Try to handle the exception
                orap.handleException(
                    new OxfordRiskAuthProvider.GenericException('Message'),
                    getAuthProviderConfig()
                );
            }

            // This method will fail the test as it should not be reached
            utl.Tst.assertExceptionHasBeenThrow();

        }catch(Exception e){

            // Assert the exception works as expected
            utl.Tst.assertExceptionMessage(
                OxfordRiskAuthProvider.GENERIC_EXCEPTION_MSG,
                String.valueOf(OxfordRiskAuthProvider.GenericException.class),
                'Message',
                e
            );
        }

    }


    /** **************************************************************************************************** **
     **                                      PRIVATE TEST DATA METHODS                                       **
     ** **************************************************************************************************** **/
    /**
     * @description Method that return a mock token response
     * @return      Mock token reponse
     */
    private static Auth.AuthProviderTokenResponse getTokenResponse(){
        return getAuthProvider().handleCallback(
            getAuthProviderConfig(),
            new Auth.AuthProviderCallbackState(
                null,
                null,
                new Map<String,String>{
                    'code' => 'NoCodeRequiredButMandatory',
                    'state'=> 'TestState'
                }
            )
        );
    }


    /**
     * @description Method to create a Auth Provider (OxfordRiskAuthProvider) class instance that is
     *              used for testing
     * @return      Class representing the Auth Provider
     */
    private static OxfordRiskAuthProvider getAuthProvider(){
        if(authProvider == null){
            authProvider = new OxfordRiskAuthProvider();
        }
        return authProvider;
    }


    /**
     * @description Method to generate the Auth Provider Config data that is used for testing
     * @return      The auth provider configuration data map
     */
    private static Map<String,String> getAuthProviderConfig(){
        if(authProviderConfig == null){
            authProviderConfig=  new Map<String,String>{
                OxfordRiskAuthProvider.BASE_URL_FIELD_NAME              => 'https://org.oxfordrisk.io',
                OxfordRiskAuthProvider.EMAIL_FIELD_NAME                 => 'test@salesforce.com.invalid',
                OxfordRiskAuthProvider.PASSWORD_FIELD_NAME              =>  OxfordRiskAuthProvider.encryptPassword('password'),
                OxfordRiskAuthProvider.SUBDOMAIN_FIELD_NAME             => 'your_subdomain',
                OxfordRiskAuthProvider.AUTH_PROVIDER_NAME_FIELD_NAME    => 'TestAuthProvider',
                OxfordRiskAuthProvider.ENABLE_ERROR_LOGGING_FIELD_NAME  => 'true',
                OxfordRiskAuthProvider.ENABLE_LOGIN_HISTORY_FIELD_NAME  => 'true'
            };
        }
        return authProviderConfig;
    }
}