package com.talentstream.response;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import com.talentstream.dto.JobRecruiterDTO;
import com.talentstream.entity.JobRecruiter;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ResponseHandler {                                          //user defined class
	
    public static ResponseEntity<Object> generateResponse(String message, HttpStatus status, Object responseObj,String email,String username,long id, String mobilenumber, String utmSource) { //object class accept any type of data. 
        Map<String, Object> map = new HashMap<String, Object>();
            map.put("message", message);
            map.put("status", status.value());
            map.put("data", responseObj);
            map.put("email", email);
            map.put("username", username);
            map.put("id", id);
            map.put("mobilenumber", mobilenumber);
            map.put("utmSource", utmSource);
            return new ResponseEntity<Object>(map,status);
    }
    public static ResponseEntity<Object> generateResponse2(String message, HttpStatus status, Object responseObj,String email,String username,long id, String mobilenumber) { //object class accept any type of data. 
        Map<String, Object> map = new HashMap<String, Object>();
            map.put("message", message);
            map.put("status", status.value());
            map.put("data", responseObj);
            map.put("email", email);
            map.put("username", username);
            map.put("id", id);
            map.put("mobilenumber", mobilenumber);
           
            return new ResponseEntity<Object>(map,status);
    }
    public static ResponseEntity<List<JobRecruiterDTO>> generateResponse1(String message, HttpStatus status,List<JobRecruiterDTO> jobRecruiters) {
    	 Map<String, Object> response = new HashMap<>();
    	    response.put("message", message);
    	    response.put("status", status.value());
    	    response.put("data", jobRecruiters);
    	    return new ResponseEntity<>(jobRecruiters, status);
    }
}