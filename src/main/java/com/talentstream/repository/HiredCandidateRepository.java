package com.talentstream.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.talentstream.entity.HiredCandidateCount;

@Repository
public interface HiredCandidateRepository extends JpaRepository<HiredCandidateCount, Long>{

}
