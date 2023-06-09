package com.regverse.auth.userDetail;

import com.regverse.clients.appuser.AppUserClient;
import com.regverse.clients.appuser.AppUserDto;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

import java.util.stream.Collectors;

@Component
public record AppUserDetailsService(
        AppUserClient appUserClient
) implements UserDetailsService {
    @Override
    public UserDetails loadUserByUsername(String email) {

        int index = email.indexOf("@");
        final String emailUserName = email.substring(0, index);
        final String emailDomain = email.substring(index + 1);

        AppUserDto user = appUserClient.loadUserByUsername(emailUserName, emailDomain);
        return new AppUserDetails(user,
                                  user.getRoleList().stream()
                                          .map(SimpleGrantedAuthority::new)
                                          .collect(Collectors.toList()));
    }
}
