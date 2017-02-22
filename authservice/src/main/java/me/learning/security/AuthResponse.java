package me.learning.security;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.io.Serializable;

@Getter
@AllArgsConstructor
public class AuthResponse implements Serializable{
    private static final long serialVersionUID = 9104047414186210425L;

    private final String token;
}
