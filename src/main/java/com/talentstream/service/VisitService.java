package com.talentstream.service;

import java.time.LocalDateTime;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.talentstream.entity.JobVisit;
import com.talentstream.repository.VisitRepository;

@Service
public class VisitService {

    @Autowired
    private VisitRepository visitRepository;

    public boolean hasVisited(long userId, long jobId) {
        return visitRepository.existsByUserIdAndJobId(userId, jobId);
    }

    public void incrementVisitCount(long jobId) {
        visitRepository.incrementVisitCount(jobId);
    }

    public void recordVisit(long userId, long jobId) {
    	LocalDateTime visitedAt = LocalDateTime.now();
        JobVisit jobVisit = new JobVisit(userId, jobId, visitedAt);
        visitRepository.save(jobVisit);
    }
}
