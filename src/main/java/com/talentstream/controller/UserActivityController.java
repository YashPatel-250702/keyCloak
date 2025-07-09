package com.talentstream.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.talentstream.service.UserActivityService;

@RestController
@RequestMapping("/api/activity")
public class UserActivityController {

    @Autowired
    private UserActivityService userActivityService;

    @PostMapping("/log")
    public ResponseEntity<String> logUserActivity(@RequestBody ActivityRequest activityRequest) {
        userActivityService.logActivity(activityRequest.getUserId(), activityRequest.getActionType());
        return ResponseEntity.ok("Log details stored in DB successfully");
    
        
    }
}

// Request Object for Logging Activity
class ActivityRequest {
    private Long userId;
    private String actionType;

    // Getters and Setters
    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public String getActionType() {
        return actionType;
    }

    public void setActionType(String actionType) {
        this.actionType = actionType;
    }
}

