package com.colossus.spsecurity.registration.token;

import com.colossus.spsecurity.appuser.AppUser;
import com.colossus.spsecurity.appuser.AppUserRepository;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
@AllArgsConstructor
public class ConfirmationTokenService {

    private final ConfirmationTokenRepository repo;
    private final AppUserRepository appUserRepository;

    public void saveConfirmationToken(ConfirmationToken token){

        repo.save(token);
    }

    public ConfirmationToken getToken(String token) {

        return repo.findByToken(token).orElseThrow(() -> new IllegalStateException("token not found"));
    }

    public void setConfirmedAt(String token) {

        ConfirmationToken confirmationToken = getToken(token);
        confirmationToken.setConfirmedAt(LocalDateTime.now());
        repo.save(confirmationToken);

        AppUser appUser = appUserRepository.getById(confirmationToken.getAppUser().getId());
        if (appUser.isEnabled()) throw new IllegalStateException("user already enabled");

        appUser.setEnabled(true);
        appUserRepository.save(appUser);
    }
}
