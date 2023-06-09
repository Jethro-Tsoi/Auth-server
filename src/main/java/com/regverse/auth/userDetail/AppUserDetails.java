package com.regverse.auth.userDetail;

import com.regverse.clients.appuser.AppUserDto;
import lombok.Builder;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Builder
@Data
public class AppUserDetails implements UserDetails {
    private AppUserDto appUser;

    private List<SimpleGrantedAuthority> collect;

    public AppUserDto getAppUser() {
        return appUser;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {

        if (collect != null) return collect;

        collect = appUser
                .getRoleList().stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
        return collect;
    }

    @Override
    public String getPassword() {
        return appUser.getPassword();
    }

    @Override
    public String getUsername() {
        return appUser.getEmail();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
