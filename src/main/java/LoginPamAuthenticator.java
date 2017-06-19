import org.apache.hive.service.auth.PasswdAuthenticationProvider;
import org.jvnet.libpam.PAM;
import org.jvnet.libpam.PAMException;

import javax.security.auth.login.LoginException;
import javax.security.sasl.AuthenticationException;

public class LoginPamAuthenticator implements PasswdAuthenticationProvider {
    private static final String LOGIN_SERVICE = "login";

    @Override
    public void Authenticate(String user, String password) throws AuthenticationException {
        try {
            PAM pam = createPam();
            pam.authenticate(user, password);
        } catch (Exception e) {
            throw new AuthenticationException("LoginPamAuthenticator: " + e.getMessage());
        }
    }

    private PAM createPam() throws LoginException {
        try {
            return new PAM(LOGIN_SERVICE);
        } catch (PAMException ex) {
            LoginException le = new LoginException("Error creating PAM");
            le.initCause(ex);
            throw le;
        }
    }
}
