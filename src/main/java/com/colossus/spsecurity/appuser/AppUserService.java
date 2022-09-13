package com.colossus.spsecurity.appuser;

import lombok.AllArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class AppUserService implements UserDetailsService {

    private final static String USER_NOT_FOUND_MSG = "user with email %s not found";
    private final AppUserRepository repo;
    private final BCryptPasswordEncoder encoder;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        return repo.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException(String.format(USER_NOT_FOUND_MSG,email)));
    }

    public String signUpUser(AppUser appUser){

        boolean isExist = repo.findByEmail(appUser.getEmail()).isPresent();

        if (isExist) throw new IllegalStateException("email already taken");

        String encodedPassword = encoder.encode(appUser.getPassword());

        appUser.setPassword(encodedPassword);

        repo.save(appUser);

        //TODO: send confirmation token

        return "it works";
    }
}
