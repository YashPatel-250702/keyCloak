package com.talentstream.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.talentstream.entity.JobVisit;
import com.talentstream.service.VisitService;

@RestController
@RequestMapping("/jobVisit")
public class JobVisitController {
	
	@Autowired
	private VisitService visitService;
	
	@PostMapping("/applicant/track-visit")
	public ResponseEntity<String> trackVisit(@RequestBody JobVisit visitRequest) {
		boolean alreadyVisited = visitService.hasVisited(
			    Long.valueOf(visitRequest.getUserId()), 
			    Long.valueOf(visitRequest.getJobId())
			);

	    if (!alreadyVisited) {
	        visitService.incrementVisitCount(Long.valueOf(visitRequest.getJobId()));
	        visitService.recordVisit(Long.valueOf(visitRequest.getUserId()), Long.valueOf(visitRequest.getJobId()));
	    }

	    return ResponseEntity.ok("Visit tracked successfully");
	}
}
