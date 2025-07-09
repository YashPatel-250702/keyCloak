package com.talentstream.repository;

import javax.transaction.Transactional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import com.talentstream.entity.JobVisit;

@Repository
public interface VisitRepository extends JpaRepository<JobVisit, Integer> {

    boolean existsByUserIdAndJobId(long userId, long jobId);
    
    @Transactional
    @Modifying
    @Query("UPDATE Job j SET j.visitorCount = j.visitorCount + 1 WHERE j.id = :jobId")
    void incrementVisitCount(@Param("jobId") long jobId);
}

