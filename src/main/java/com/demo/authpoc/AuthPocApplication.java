package com.demo.authpoc;

import com.demo.authpoc.config.AppProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(AppProperties.class)
public class AuthPocApplication {
    public static void main(String[] args) {
        SpringApplication.run(AuthPocApplication.class, args);
    }
}
