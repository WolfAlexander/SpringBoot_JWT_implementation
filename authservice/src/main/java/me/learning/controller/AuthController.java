package me.learning.controller;

import me.learning.security.AuthRequest;
import me.learning.security.AuthResponse;
import me.learning.security.RSAJwtTokenFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController {
    private static Logger logger = LoggerFactory.getLogger(AuthController.class);

    private final String jwtTokenHeader = "Authorization";

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private AuthenticationManager authenticationManager;

    /**
     * Generates a token when user tries to login
     * @param authRequest - user credentials
     * @throws AuthenticationException if authentication failed
     * @return ResponseEntity with a custom response and status
     */
    @PostMapping("/auth")
    public ResponseEntity<?> generateJwtToken(@RequestBody AuthRequest authRequest){
        logger.info("Incomming Request: " + authRequest.getUsername() + " " + authRequest.getPassword());

        performUsernamePasswordAuthentication(authRequest.getUsername(), authRequest.getPassword());

        final String jwtToken = RSAJwtTokenFactory.generateTokenForAUser(getUserDetailsByUsername(authRequest.getUsername()));

        return new ResponseEntity<Object>(new AuthResponse(jwtToken), HttpStatus.OK);
    }



    /**
     * Perform Spring Security authentication and adding to SecurityContext
     * @param username - entered username by user
     * @param password - entered password by user
     */
    private void performUsernamePasswordAuthentication(String username, String password){
        final Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password)
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    /**
     * @param username - given username
     * @return UserDetails that contains all information about the user
     */
    private UserDetails getUserDetailsByUsername(String username){
        return userDetailsService.loadUserByUsername(username);
    }
}
