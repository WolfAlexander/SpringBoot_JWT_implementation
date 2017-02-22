package me.learning.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ResourcesController {
    private static Logger logger = LoggerFactory.getLogger(ResourcesController.class);

    @GetMapping("/info")
    @PreAuthorize("hasRole('USER')")
    public String info(){
        return "This is info";
    }

    @GetMapping("/secret")
    @PreAuthorize("hasRole('ADMIN')")
    public String secretInfo(){
        logger.error("Security breach!");
        return "This is secret!";
    }
}
