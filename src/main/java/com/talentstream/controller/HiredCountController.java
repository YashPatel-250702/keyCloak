package com.talentstream.controller;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.talentstream.entity.HiredCandidateCount;
import com.talentstream.repository.HiredCandidateRepository;

@RestController
@RequestMapping("/api")
public class HiredCountController {
	
	@Autowired
	private HiredCandidateRepository repo;
	
	@GetMapping("/hiredCount/{id}")
	public ResponseEntity<?> getHiredCount(@PathVariable long id) {
	    Optional<HiredCandidateCount> count = repo.findById(id);
	    if (count.isEmpty()) {
	        return ResponseEntity
	                .status(HttpStatus.NOT_FOUND)
	                .body("ID not found");
	    }
	    return ResponseEntity.ok(count.get().getHiredCount());
	}


}
