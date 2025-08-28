// Execute the example methods
getClients();
getClientsByLastName('Taylor');


/**
 * Example to return a full list of clients
 */
private void getClients(){
    
    // The name of the named credential (!! case sensitive !!)
    // Make sure you have access through a permission set for this one
    String namedCredentialName = 'OR';
    
    // the specific endpoint for the API (What comes after the Base URL)
    String apiEndpoint         = '/clients';

    // Generate the endpoint
    String endpoint = String.format(
        'callout:{0}{1}', 
        new String[]{
            namedCredentialName,
            apiEndpoint
        }
    );
    
    executeAndHandleRestCall('GET', endpoint);
}


/**
 * Example to add URL parameters to search for a specific client
 */
private void getClientsByLastName(String lastName){
    
    // The name of the named credential (!! case sensitive !!)
    // Make sure you have access through a permission set for this one
    String namedCredentialName = 'OR';
    
    // the specific endpoint for the API (What comes after the Base URL)
    String apiEndpoint         = '/clients';

    // Generate the endpoint
    String endpoint = String.format(
        'callout:{0}{1}?last_name={2}', 
        new String[]{
            namedCredentialName,
            apiEndpoint,
            EncodingUtil.urlDecode(lastName, 'UTF-8')
        }
    );
    
    executeAndHandleRestCall('GET', endpoint);
}


/**
 * Method to execute the REST calls
 */
void executeAndHandleRestCall(String method, String endpoint){
    HttpRequest request = new HttpRequest();
    request.setEndPoint(endpoint);
    request.setMethod(method);
    request.setHeader('Content-Type','application/json');
    HttpResponse res = new HTTP().send(request);
    System.debug(res.getStatusCode());
    System.debug(res.getBody());
}