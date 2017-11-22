package org.cloudfoundry.identity.uaa.authentication;

import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.springframework.security.core.AuthenticationException;

public class MfaAuthenticationRequiredException extends AuthenticationException {
    private final UaaUser user;
    private final UaaAuthentication authentication;

    public MfaAuthenticationRequiredException(UaaAuthentication authentication, UaaUser user, String msg) {
        super(msg);
        this.authentication = authentication;
        this.user = user;
    }

    public UaaAuthentication getAuthentication() {
        return authentication;
    }

    public UaaUser getUser() {
        return user;
    }
}
