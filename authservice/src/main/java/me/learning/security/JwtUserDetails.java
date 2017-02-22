package me.learning.security;

import me.learning.entity.RoleEntity;
import me.learning.entity.UserEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

public class JwtUserDetails implements UserDetails {
    private final Long id;
    private final String username;
    private final String password;
    private final Collection<GrantedAuthority> roles;

    public JwtUserDetails(Long id, String username, String password, Collection<GrantedAuthority> roles) {
        this.id = id;
        this.username = username;
        this.password = password;
        this.roles = roles;
    }

    public JwtUserDetails(UserEntity userEntity){
        this.id = userEntity.getId();
        this.username = userEntity.getUsername();
        this.password = userEntity.getPassword();
        this.roles = mapToGrantedAuthorities(userEntity.getRoles());
    }

    private List<GrantedAuthority> mapToGrantedAuthorities(List<RoleEntity> roles){
        return roles.stream()
                .map(r -> new SimpleGrantedAuthority(r.getName()))
                .collect(Collectors.toList());
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return roles;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
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
