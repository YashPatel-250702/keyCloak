package com.talentstream.service;


import java.time.LocalDateTime;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.talentstream.entity.UserActivity;
import com.talentstream.repository.UserActivityRepository;

@Service
public class UserActivityService {

	 @Autowired
	    private UserActivityRepository userActivityRepository;

	    public void logActivity(Long userId, String actionType) {
	        UserActivity activity = new UserActivity(userId, actionType, LocalDateTime.now());
	        userActivityRepository.save(activity);
	    }
}

