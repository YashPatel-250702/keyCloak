package com.talentstream.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
 
import com.talentstream.entity.ApplicantStatusHistory;


public interface ApplicantStatusHistoryRepository extends JpaRepository<ApplicantStatusHistory, Long> {
    List<ApplicantStatusHistory> findByApplyJob_ApplyjobidOrderByChangeDateDesc(long applyjobid);
}
