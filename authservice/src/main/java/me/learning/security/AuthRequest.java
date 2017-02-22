package me.learning.security;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;

@Getter
@Setter
@AllArgsConstructor
public class AuthRequest implements Serializable {
    private static final long serialVersionUID = 7622816671628629971L;

    private String username;
    private String password;
}
