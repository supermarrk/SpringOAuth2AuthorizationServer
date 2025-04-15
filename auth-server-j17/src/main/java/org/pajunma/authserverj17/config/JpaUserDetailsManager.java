package org.pajunma.authserverj17.config;

import lombok.RequiredArgsConstructor;
import org.pajunma.authserverj17.entities.AppUser;
import org.pajunma.authserverj17.persistence.UserRepository;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.HashSet;

@RequiredArgsConstructor
@Service
public class JpaUserDetailsManager implements UserDetailsManager {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AppUser appUser = userRepository.findByUsername(username);
        if (!appUser.getUsername().equals(username)) {
            throw new UsernameNotFoundException("Access Denied");
        }
        Collection<GrantedAuthority> authoriies = new HashSet<>();
        appUser.getAuthorities().forEach(auth -> authoriies.add(new SimpleGrantedAuthority(auth.getAuthority())));
        return new User(appUser.getUsername(), appUser.getPassword(), appUser.getEnabled(), appUser.getAccountNonExpired(),
                appUser.getCredentialsNonExpired(), appUser.getAccountNonLocked(), authoriies);
    }

    @Override
    public void createUser(UserDetails user) {
    }

    @Override
    public void updateUser(UserDetails user) {
    }

    @Override
    public void deleteUser(String username) {
    }

    @Override
    public void changePassword(String oldPassword, String newPassword) {
    }

    @Override
    public boolean userExists(String username) {
        AppUser user = userRepository.findByUsername(username);
        if (user.getUsername().equals(username)) {
            return true;
        }
        return false;
    }

}
