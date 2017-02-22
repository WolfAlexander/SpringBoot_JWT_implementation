package me.learning;

import me.learning.entity.RoleEntity;
import me.learning.entity.UserEntity;
import me.learning.repository.RoleRepository;
import me.learning.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.data.repository.Repository;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.StreamSupport;

@SpringBootApplication
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class LaunchAuthService {
    public static void main(String[] args) {
        SpringApplication.run(LaunchAuthService.class, args);
    }

    @Bean
    public CommandLineRunner initDB(UserRepository userRepository, RoleRepository roleRepository){
        return (args) ->{
            RoleEntity userRole = new RoleEntity("ROLE_USER");
            RoleEntity adminRole = new RoleEntity("ROLE_ADMIN");

            List<RoleEntity> userRoles = new ArrayList<>();
            userRoles.add(userRole);

            List<RoleEntity> adminRoles = new ArrayList<>();
            adminRoles.add(adminRole);
            adminRoles.add(userRole);

            roleRepository.save(userRole);
            roleRepository.save(adminRole);

            userRepository.save(new UserEntity("user", "password", userRoles));
            userRepository.save(new UserEntity("admin", "password", adminRoles));
            UserEntity user = userRepository.findByUsername("user");

            StreamSupport.stream(userRepository.findAll().spliterator(), false).forEach(System.out::println);
            System.out.println("FindByUsername: " + user);
        };
    }
}
