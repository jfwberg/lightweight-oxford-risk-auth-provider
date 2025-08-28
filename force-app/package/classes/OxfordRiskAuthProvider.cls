/**
 * @author         Justus van den Berg (jfwberg@gmail.com)
 * @date           October 2025
 * @copyright      (c) 2025 Justus van den Berg
 * @license        MIT (See LICENSE file in the project root)
 * @description    A lightweight Auth Provider to connect to the Oxford Risk APIs through a Named Credential
 * @note           In order to use the (error) logging functions tt is required that the "Lightweight - Auth Provider Util
 *                 v2" package is installed.
 * @note           "Per User" mode is not supported
 */
@SuppressWarnings('PMD.CyclomaticComplexity,PMD.AvoidGlobalModifier')
global with sharing class OxfordRiskAuthProvider extends Auth.AuthProviderPluginClass{

    /** **************************************************************************************************** **
     **                                          PRIVATE VARIABLES                                           **
     ** **************************************************************************************************** **/
    // The type of flow (Initial or Refresh)
    private String flowType;

    // For debugging purposes extract the callout data
    private utl.Rst tokenCallout;

    // The optional auth provider util for error logging and per user principal (requires the "Lightweight - Auth Provider Util v2" package)
    // If you dont want this depencency, disable the options "Enable Error Logging", "Enabled Per user principal" and "Enabled Per User Login Logging" in the Custom Auth Provider Setup.
    private Callable authProviderUtil;

    // The details of the logged in user
    private String        loggedInUserId   = UserInfo.getUserId();
    private Auth.UserData loggedInUserData = new Auth.UserData(
        UserInfo.getUserId(),    // User Id
        UserInfo.getFirstName(), // First Name
        UserInfo.getLastName(),  // Last Name
        UserInfo.getFirstName() + ' ' +  UserInfo.getLastName(), // Full Name (user name here)
        UserInfo.getUserEmail(), // Email Address
        null,                    // Link
        UserInfo.getUserName(),  // Username
        UserInfo.getLocale(),    // Locale
        null,                    // Provider
        null,                    // Site login
        null                     // Attribute map
    );


    /** **************************************************************************************************** **
     **                                          PRIVATE CONSTANTS                                           **
     ** **************************************************************************************************** **/
    // Auth provider details

    @TestVisible private final static String AUTH_PROVIDER_NAME_FIELD_NAME   = String.valueOf(OxfordRiskAuthProvider__mdt.Auth_Provider_Name__c);

    // Application details
    @TestVisible private final static String BASE_URL_FIELD_NAME             = String.valueOf(OxfordRiskAuthProvider__mdt.Base_Url__c);

    // Connection details
    @TestVisible private final static String EMAIL_FIELD_NAME                = String.valueOf(OxfordRiskAuthProvider__mdt.Email__c);
    @TestVisible private final static String PASSWORD_FIELD_NAME             = String.valueOf(OxfordRiskAuthProvider__mdt.Password__c);
    @TestVisible private final static String SUBDOMAIN_FIELD_NAME            = String.valueOf(OxfordRiskAuthProvider__mdt.Subdomain__c);

    // Setup switches for the "Lightweight - Auth Provider Util package"
    @TestVisible private final static String ENABLE_ERROR_LOGGING_FIELD_NAME = String.valueOf(OxfordRiskAuthProvider__mdt.Enable_Error_Logging__c);
    @TestVisible private final static String ENABLE_LOGIN_HISTORY_FIELD_NAME = String.valueOf(OxfordRiskAuthProvider__mdt.Enable_Login_History__c);

    // This will generate the GUID that is used to identify this specific transaction so it can be followed through the logs
    @TestVisible private final static String GUID = utl.Rst.guid();

    // The identifer for the primary key of the encryption key in the encryption key store
    @TestVisible private final static String ENCRYPTION_KEY_STORE_KEY = 'PrimaryKey';

    // Parameter names
    @TestVisible private final static String PARAM_NAME_STATE   = 'state';

    // Test Cookie header
    @TestVisible private final static String TEST_COOKIE_HEADER = 'sid=[SESSION_ID];';

    // Any messages go here
    @TestVisible private final static String GENERIC_EXCEPTION_MSG      = 'A {0} was thrown with the message: {1}';
    @TestVisible private final static String NO_USER_MAPPING_MSG        = 'Nu User Mapping Record was found for Auth Proivder "{0}" with user "{1}"';
    @TestVisible private final static String MISSING_UTIL_PACKAGE_MSG   = 'Issue whilst instantiating the AuthProviderUtil class. Make sure the "Lightweight - Auth Provider Util v2" package is installed. Alternatively, DISABLE the options "Enable Error Logging", "Enable Per user principal" and "Enable Per User Login Logging" in the Custom Auth Provider Setup.';
    @TestVisible private final static String INVALID_TOKEN_RESPONSE_MSG = 'Unexpected response when calling the token endpoint: {0}';


    /** **************************************************************************************************** **
     **                                       PUBLIC INTERFACE METHODS                                       **
     ** **************************************************************************************************** **/
    /**
     * @description     Returns the URL where the user is redirected for authentication.
     * @param           authProviderConfiguration The configuration items for the custom authentication
     *                                            provider that have been configured in the custom
     *                                            metadata type.
     * @param           stateToPropagate          The state passed in to initiate the authentication
     *                                            request for the user
     * @return          The URL of the page where the user is redirected for authentication.
     * @false-positives The URL is generated at a known source and no danger. It's not user updateable.
     *                  Also the remote site settings will prevent any unauthorised endpoint call-outs
     */
    @SuppressWarnings('PMD.ApexOpenRedirect')
    public PageReference initiate(Map<String,String> authProviderConfiguration, String stateToPropagate){

        // Get the standard auth provider endpoint url
        PageReference pageReference = this.getSfdcCallbackURL(authProviderConfiguration);

        // Add the state parameter
        pageReference.getParameters().put(PARAM_NAME_STATE, stateToPropagate);

        // Return the pageReference
        return pageReference;
    }


    /**
     * @description Uses the authentication provider’s supported authentication protocol to return an
     *              OAuth access token, OAuth secret or refresh token, and the state passed in when the
     *              request for the current user was initiated.
     * @param       authProviderConfiguration The configuration items for the custom authentication
     *                                        provider that have been configured in the custom metadata
     *                                        type.
     * @param       callbackState             The class that contains the HTTP headers, body, and
     *                                        queryParams of the authentication request.
     * @return      Creates an instance of the AuthProviderTokenResponse class
     * @note        There is no refresh token in the OAUth 2.0 JWT Client Authentication flow so we
     *              just ignore this value or put in a random, invalid value.
     */
    public Auth.AuthProviderTokenResponse handleCallback(Map<String,String> authProviderConfiguration, Auth.AuthProviderCallbackState callbackState){
        try{
            // Set the flow type
            this.flowType = 'Initial';

            // Retrieve a new token from the token endpoint
            TokenResponse tokenResponse = this.retrieveToken(authProviderConfiguration);

            // Manage the login history
            this.handleInsertHistoryRecord(
                authProviderConfiguration,
                'Initial',
                String.isNotBlank(tokenResponse.access_token),
                authProviderConfiguration.get(AUTH_PROVIDER_NAME_FIELD_NAME)?.trim(),
                this.tokenCallout
            );

            // Error with the token, purposely thrown here to manage proper error logging
            if(String.isBlank(tokenResponse.access_token)){
                throw new TokenException(String.format(INVALID_TOKEN_RESPONSE_MSG, new String[]{tokenCallout.getResponse().getBody()}));
            }



            // Return the the token response, there is no refresh token so we just set a random value
            return new Auth.AuthProviderTokenResponse(
                authProviderConfiguration.get(AUTH_PROVIDER_NAME_FIELD_NAME)?.trim(),
                tokenResponse.access_token,
                loggedInUserId, // The logged in user is used for the refresh flow to know what user to login (if per user enabled else ignored)
                callbackState.queryParameters.get(PARAM_NAME_STATE)
            );
        }catch(Exception e){
            handleException(e, authProviderConfiguration);
        }

        // Unreachable statement to please the apex compiler
        return null;
    }


    /**
     * @description Returns a new access token, which is used to update an expired access token.
     * @param       authProviderConfiguration The configuration items for the custom authentication
     *                                        provider that have been configured in the custom metadata
     *                                        type.
     * @param       refreshToken              The refresh token for the user who is logged in.
     * @return      Returns the new access token, or an error message if an error occurs.
     * @note        There is no refresh token in the OAUth 2.0 JWT Client Authentication flow so we
     *              just ignore this value or put in a random, invalid value.
     */
    public override Auth.OAuthRefreshResult refresh(Map<String,String> authProviderConfiguration, String refreshToken){
        try{

            // Retrieve a new token from the token endpoint
            TokenResponse tokenResponse = this.retrieveToken(authProviderConfiguration);

            // Manage the login history
            this.handleInsertHistoryRecord(
                authProviderConfiguration,
                'Refresh',
                String.isNotBlank(tokenResponse.access_token),
                authProviderConfiguration.get(AUTH_PROVIDER_NAME_FIELD_NAME)?.trim(),
                this.tokenCallout
            );

            // Error with the token, purposely thrown here to manage proper error logging
            if(String.isBlank(tokenResponse.access_token)){
                throw new TokenException(String.format(INVALID_TOKEN_RESPONSE_MSG, new String[]{tokenCallout.getResponse().getBody()}));
            }

            // Return the (refresh) token response
            return new Auth.OAuthRefreshResult(
                tokenResponse.access_token,
                refreshToken
            );

        }catch(Exception e){
            handleException(e, authProviderConfiguration);
        }

        // Unreachable statement to please the apex compiler
        return null;
    }


    /**
     * @description Returns information from the custom authentication provider about the current user.
     *              This information is used by the registration handler and in other authentication
     *              provider flows.
     * @param       authProviderConfiguration The configuration items for the custom authentication
     *                                        provider that have been configured in the custom metadata
     *                                        type.
     * @param       response                  The OAuth access token, OAuth secret or refresh token,
     *                                        and state provided by the authentication provider to
     *                                        authenticate the current user.
     * @return      Creates a new instance of the Auth.UserData class.
     * @note        User data is not being used in the OAUth 2.0 JWT Client Authentication flow as it
     *              is a system to system integration. As some basic required info I put in an
     *              integration user.
     */
    public Auth.UserData getUserInfo(Map<string,string> authProviderConfiguration, Auth.AuthProviderTokenResponse response) {
        return loggedInUserData;
    }


    /**
     * @description Returns the custom metadata type API name for a custom OAuth-based authentication
     *              provider for single sign-on to Salesforce.
     * @return      The custom metadata type API name for the authentication provider.
     */
    public String getCustomMetadataType() {
        return String.valueOf(OxfordRiskAuthProvider__mdt.getSObjectType());
    }


    /** **************************************************************************************************** **
     **                                       PRIVATE SUPPORT METHODS                                        **
     ** **************************************************************************************************** **/
    /**
     * @description     Method to Generate the standard Salesforce Auth Provider callback URL for the
     *                  specific Auth Provider Name.
     * @param           authProviderConfiguration The configuration items for the custom authentication
     *                                            provider that have been configured in the custom
     *                                            metadata type.
     * @return          The Auth Provider's callback URL
     * @false-positives The URL is generated at a known source and no danger. It's not user updateable.
     *                  Also the remote site settings will prevent any unauthorised endpoint call-outs
     */
    @SuppressWarnings('PMD.ApexOpenRedirect')
    private PageReference getSfdcCallbackURL(Map<String,String> authProviderConfiguration){

        // By default generate the Standard Salesforce Callback URL for the Auth Provider
        return new PageReference(
            URL.getOrgDomainUrl().toExternalForm() + '/services/authcallback/' + authProviderConfiguration.get(AUTH_PROVIDER_NAME_FIELD_NAME)?.trim()
        );
    }


    /**
     * @description Method to parse the token response JSON into a TokenResponse Object
     * @param       tokenResponseJSON The JSON response returned from the Authorisation Server
     * @return      A TokenResponse Object
     */
    private TokenResponse parseTokenResponse(String tokenResponseJSON){
        return (TokenResponse) JSON.deserialize(tokenResponseJSON, TokenResponse.class);
    }


    /**
     * @description Method that generates the HTTP Request to retrieve an access token
     *              from the configured token endpoint.
     * @param       authProviderConfiguration The configuration items for the custom authentication
     *                                        provider that have been configured in the custom metadata
     *                                        type.
     * @return      A TokenResponse with the access token
     * @throws      TokenException            There is an error in parsing the token response
     */
    private TokenResponse retrieveToken(Map<String,String> authProviderConfiguration){

        // Call SF token endpoint, extract for error handling
        this.tokenCallout = new utl.Rst()
            .setMethod('POST')
            .setEndpoint(authProviderConfiguration.get(BASE_URL_FIELD_NAME) + '/tokens')
            .setBody(
                JSON.serialize(
                    new Map<String,String>{
                        'email'     => authProviderConfiguration.get(EMAIL_FIELD_NAME),
                        'password'  => decryptPassword(authProviderConfiguration.get(PASSWORD_FIELD_NAME)),
                        'subdomain' => authProviderConfiguration.get(SUBDOMAIN_FIELD_NAME)
                    }
                )
            )
            .call();

        // Parse the response into a token response
        return this.parseTokenResponse(this.tokenCallout?.getResponse()?.getBody());
    }


    /** **************************************************************************************************** **
     **                                       PRIVATE UTILITY METHODS                                        **
     ** **************************************************************************************************** **/
    /**
     * @description Method that logs an exception and transforms any exception type into a
     *              GenericException
     * @param       e                         The exception that is thrown and needs to be handled
     * @param       authProviderConfiguration The configuration items for the custom authentication
     *                                        provider that have been configured in the custom metadata
     *                                        type.
     * @throws      GenericException          Always
     */
    @TestVisible
    private void handleException(Exception e, Map<String,String> authProviderConfiguration){

        // Generate a generic exception message for the error handling and to be thrown to the user
        String exceptionMessage = String.format(GENERIC_EXCEPTION_MSG, new String[]{e.getTypeName(), e.getMessage()});

        // If logging is enabled use the "Lightweight - Auth Provider Util v2" method to insert an error log
        // This does mean a dependency with a different package, simply remove this code if you don't
        // want to install the dependency
        if(Boolean.valueOf(authProviderConfiguration.get(ENABLE_ERROR_LOGGING_FIELD_NAME))){

            getAuthProviderUtil().call('insertLog', new Map<String, Object> {
                'authProviderName' => authProviderConfiguration.get(AUTH_PROVIDER_NAME_FIELD_NAME)?.trim(),
                'userId'           => loggedInUserId,
                'logId'            => GUID,
                'message'          => exceptionMessage
            });
        }

        // Throw the new generic exception to the user#
        throw new GenericException(exceptionMessage);
    }


    /**
     * @description Method to get an instance of the AuthProviderUtil class.
     *              This option requires the "Lightweight - Auth Provider Util v2" (04t4K000002Jv1tQAC)
     *              package to be installed
     * @return      Instance of the AuthProviderUtil class
     * @throws      GenericException The lwt.AuthProviderUtil class does not exist.
     */
    @TestVisible
    private Callable getAuthProviderUtil(){
        if(this.authProviderUtil == null){

            // Allow for testing a callable method
            if(Test.isRunningTest()){return (Callable) utl.Clbl.getInstance();}

            // Dymaically instatiate class
            this.authProviderUtil = (Callable) Type.forName('lwt.AuthProviderUtil')?.newInstance();

            // Throw an error if the package is not installed
            // Add Test check here so the test does not fail in case the package is installed
            if(this.authProviderUtil == null){
                throw new GenericException(MISSING_UTIL_PACKAGE_MSG);
            }
        }
        return this.authProviderUtil;
    }


    /**
     * @description Method that generates the JWT, JWS and HTTP Request to retrieve an access token
     *              from the configured token endpoint.
     * @param       authProviderConfiguration The configuration items for the custom authentication
     *                                        provider that have been configured in the custom metadata
     *                                        type.
     * @param       flowType                  The type of login flow (Initial or Refresh)
     * @param       success                   Inidcator if the login was successful or not
     * @param       providerType              Optional description of the provider. This is handy when you
     *                                        have chained callouts.
     * @param       callout                   The callout details for error logging
     */
    @SuppressWarnings('PMD.ExcessiveParameterList')
    private void handleInsertHistoryRecord(Map<String,String> authProviderConfiguration, String flowType, Boolean success, String providerType, utl.Rst callout){
        // If login history is enabled, create a login history entry
        if(Boolean.valueOf(authProviderConfiguration.get(ENABLE_LOGIN_HISTORY_FIELD_NAME))){
            getAuthProviderUtil().call('insertLoginHistoryRecord', new Map<String, Object> {
                'authProviderName' => authProviderConfiguration.get(AUTH_PROVIDER_NAME_FIELD_NAME)?.trim(),
                'userId'           => loggedInUserId,
                'flowType'         => flowType,
                'timestamp'        => Datetime.now(),
                'success'          => success,
                'providerType'     => providerType,
                'loginInfo'        => success ? null : callout?.getResponse()?.getBody()
            });
        }
    }


    /**
     * @description Method to get the encryption key from the protected custom setting
     * @return      Base64 Encoded Encryption key
     */
    private static String getEncryptionKey(){

        OxfordRiskEncryptionKey__c encryptionKeyRecord = OxfordRiskEncryptionKey__c.getInstance(ENCRYPTION_KEY_STORE_KEY);

        // On the first instance the encryption key
        if(encryptionKeyRecord == null){
            rotateEncryptionKey();

            encryptionKeyRecord = OxfordRiskEncryptionKey__c.getInstance(ENCRYPTION_KEY_STORE_KEY);
        }

        return encryptionKeyRecord.Value__c;
    }


    /**
     * @description Method to decrypt a password with the encryption key from the store
     * @param encryptedPassword The password to decrypt
     * @return The plain text password
     */
    private static String decryptPassword(String encryptedPassword){
        return String.valueOf(
            Crypto.decryptWithManagedIV(
                'AES256',
                EncodingUtil.base64Decode(getEncryptionKey()),
                EncodingUtil.base64Decode(encryptedPassword)
            ).toString()
        );
    }


    /** **************************************************************************************************** **
     **                                         GLOBAL UTILITY CLASSES                                       **
     ** **************************************************************************************************** **/
    /**
     * @description Method to encrypt a password
     * @param password The password to encrypt
     * @return      A base64 encoded representation of the encrypted password
     */
     global static String encryptPassword(String password){
        return EncodingUtil.base64Encode(
            Crypto.encryptWithManagedIV(
                'AES256',
                EncodingUtil.base64Decode(getEncryptionKey()),
                Blob.valueOf(password)
            )
        );
    }


    /**
     * @description Method to rotate the encryption key
     * @note        !! This invalidates all passwords encrypted with the current encryption key !!
     */
    global static void rotateEncryptionKey(){
        upsert as system new OxfordRiskEncryptionKey__c(
            name  = ENCRYPTION_KEY_STORE_KEY,
            Value__c = EncodingUtil.base64Encode(Crypto.generateAesKey(256))
        );
    }


    /** **************************************************************************************************** **
     **                                      PRIVATE EXCEPTION CLASSES                                       **
     ** **************************************************************************************************** **/
    /**
     * @description Custom Exception thrown when there is an issue generating the token.
     */
    @TestVisible
    private class TokenException  extends Exception{}


    /**
     * @description Custom Exception thrown when there is an issue related the subject
     */
    @TestVisible
    private class SubjectException extends Exception{}


    /**
     * @description Custom Exception thrown when there is an issue generating the token.
     */
    @TestVisible
    private class GenericException extends Exception{}


    /** **************************************************************************************************** **
     **                                    PRIVATE DATA STRUCTURE CLASSES                                    **
     ** **************************************************************************************************** **/
    /**
     * @description     Class representing the data strcuture of an OAuth Token Response as described in standard:
     *                  https://datatracker.ietf.org/doc/html/rfc6749#section-4.2.2
     * @false-positives Namings conventions have to match the JSON response format in order to properly
     *                  deserialize.  In this case the naming conventions will not follow standard
     *                  conventions to accomodate this
     */
    @SuppressWarnings('PMD.VariableNamingConventions,PMD.FieldNamingConventions')
    @TestVisible
    private class TokenResponse{

        // Required
        public String access_token;
        public String token_type;

        // Optional
        public String expires_in;
    }
}