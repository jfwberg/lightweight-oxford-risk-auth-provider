// !! Update this script as soon as you have used it to not expose the password !!
String password = 'your_password_here';

// Output the encrypted password
System.debug(
    oauth.OxfordRiskAuthProvider.encryptPassword(password)
);