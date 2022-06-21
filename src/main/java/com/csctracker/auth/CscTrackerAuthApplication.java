package com.csctracker.auth;

import com.csctracker.configs.MetricGenerator;
import com.csctracker.configs.Prometheus;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Import;

@SpringBootApplication
@ComponentScan(basePackages = {"com.csctracker.auth", "com.csctracker"})
@Import({
        Prometheus.class,
        MetricGenerator.class
})
public class CscTrackerAuthApplication {
    public static void main(String[] args) {
        SpringApplication.run(CscTrackerAuthApplication.class, args);
    }
}
