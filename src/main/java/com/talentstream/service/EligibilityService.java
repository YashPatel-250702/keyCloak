package com.talentstream.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.talentstream.entity.Eligibility;
import com.talentstream.repository.EligibilityRepository;

@Service
public class EligibilityService {
    EligibilityRepository eligibilityRepository;

    // Initializes the EligibilityService with the provided eligibility repository.
    @Autowired
    public EligibilityService(EligibilityRepository eligibilityRepository) {
        this.eligibilityRepository = eligibilityRepository;
    }

    // Saves the provided eligibility record to the repository.
    public Eligibility saveEligibility(Eligibility eligibility) {
        return eligibilityRepository.save(eligibility);
    }

}
