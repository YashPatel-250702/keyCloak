package com.talentstream.healthcheck;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
public class HealthCheckScheduler {
 
    private final HealthCheckService healthCheckService;
 
    public HealthCheckScheduler(HealthCheckService healthCheckService) {
        this.healthCheckService = healthCheckService;
    }
 
   
    @Scheduled(fixedRate = 10000000) // 10 seconds interval
  //@Scheduled(fixedRate = 300000) // 5 minutes interval (adjust as needed)
  
    public void healthCheck() {
        System.out.println("Performing backend health check...");
        if (healthCheckService.isBackendHealthy()) {
            System.out.println("Backend is healthy");
        } else {
            System.out.println("Backend is not healthy");
        }
    }
}