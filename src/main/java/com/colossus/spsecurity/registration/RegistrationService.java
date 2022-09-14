package com.colossus.spsecurity.registration;

import com.colossus.spsecurity.appuser.AppUser;
import com.colossus.spsecurity.appuser.AppUserRole;
import com.colossus.spsecurity.appuser.AppUserService;
import com.colossus.spsecurity.registration.token.ConfirmationToken;
import com.colossus.spsecurity.registration.token.ConfirmationTokenService;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.PostMapping;

import java.time.LocalDateTime;

@Service
@AllArgsConstructor
public class RegistrationService {

    private final AppUserService appUserService;
    private final EmailValidator emailValidator;
    private final ConfirmationTokenService confirmationTokenService;

    @PostMapping
    public String register(RegistrationRequest request) {
        boolean isValidEmail = emailValidator.test(request.getEmail());
        if (!isValidEmail) throw new IllegalStateException(String.format("%s isn't valid", request.getEmail()));
        return appUserService.signUpUser(new AppUser(
                request.getFirstName(),
                request.getLastName(),
                request.getEmail(),
                request.getPassword(),
                AppUserRole.USER));
    }

    @Transactional
    public String confirmToken(String token){
        ConfirmationToken confirmationToken = confirmationTokenService.getToken(token);

        if (confirmationToken.getConfirmedAt() != null){
            throw new IllegalStateException("email already confirmed");
        }

        LocalDateTime expiredAt = confirmationToken.getExpiresAt();

        if (expiredAt.isBefore(LocalDateTime.now())) throw new IllegalStateException("token expired");

        confirmationTokenService.setConfirmedAt(token);

        return "confirmed";
    }
}
