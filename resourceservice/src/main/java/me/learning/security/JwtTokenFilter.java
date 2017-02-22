package me.learning.security;

import net.minidev.json.JSONArray;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;

/**
 * This class represents a toke filter that will take care
 * of all incoming requests, check their security token and set security context
 *
 * @author WolfAlexander nikal@kth.se
 */
public class JwtTokenFilter extends OncePerRequestFilter {
    private static Logger logger = LoggerFactory.getLogger(JwtTokenFilter.class);
    private final String tokenHeader = "Authorization";

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
        String authHeader = httpServletRequest.getHeader(this.tokenHeader);

        try{
            RSAEncryptedRSASignedJWT authToken = new RSAEncryptedRSASignedJWT(authHeader);
            authToken.decrypt();

            if(authToken.isTokenValid())
                this.setSecurityContext(authToken);
        }catch (RSAEncryptedRSASignedJWTException | NullPointerException e){
            logger.error("Token error occurred during filtering: " + e.getMessage(), e);
            throw new IllegalArgumentException("Invalid token has been provided!");
        }

        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }

    private void setSecurityContext(RSAEncryptedRSASignedJWT token){
        if(token != null){
            if(SecurityContextHolder.getContext().getAuthentication() == null){
                JwtUserDetails user = (JwtUserDetails) getUserDetails(token);
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }else
            throw new NullPointerException("No token have been provided to security context!");
    }

    private Collection<GrantedAuthority> getGrantedAuthoritiesFromJsonToken(RSAEncryptedRSASignedJWT token){
        Collection<GrantedAuthority> authorities = new ArrayList<>();
        JSONArray jsonList = (JSONArray) token.getTokenClaims().getClaim("scope");

        for (Object node : jsonList)
            authorities.add(new SimpleGrantedAuthority(node.toString()));

        return authorities;
    }

    private UserDetails getUserDetails(RSAEncryptedRSASignedJWT token){
        String username = token.getTokenClaims().getSubject();
        Collection<GrantedAuthority> roles = this.getGrantedAuthoritiesFromJsonToken(token);

        return new JwtUserDetails(1L, username, null, roles);
    }
}
