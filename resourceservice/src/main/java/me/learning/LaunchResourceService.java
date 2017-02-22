package me.learning;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.PropertySource;

@SpringBootApplication
public class LaunchResourceService {
    public static void main(String[] args) {
        SpringApplication.run(LaunchResourceService.class, args);
    }
}
