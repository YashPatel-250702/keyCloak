package com.talentstream.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.talentstream.entity.ApplicantTest;
import com.talentstream.service.ApplicantTestService;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/applicant1")
public class ApplicantTestController {

    @Autowired
    private ApplicantTestService applicantTestService;

    @PostMapping("/saveTest/{applicantId}")
    public String saveTest(@RequestBody ApplicantTest test,@PathVariable Long applicantId) {
        ApplicantTest savedTest = applicantTestService.saveTest(test,applicantId);
        return "Test Details Saved Successfully";
    }
    
    @GetMapping("/tests/{applicantId}")
    public ResponseEntity<List<ApplicantTest>> getTestsByApplicantId(@PathVariable Long applicantId) {
        List<ApplicantTest> tests = applicantTestService.getTestsByApplicantId(applicantId);
        if (tests.isEmpty()) {
            return ResponseEntity.noContent().build(); // Return 204 No Content if no tests are found
        }
        return ResponseEntity.ok(tests); // Return 200 OK with the list of tests
    }

    @GetMapping("/test/test1/{id}")
    public ResponseEntity<ApplicantTest> getTestById(@PathVariable Long id) {
        Optional<ApplicantTest> test = applicantTestService.getTestById(id);
        return test.map(ResponseEntity::ok).orElseGet(() -> ResponseEntity.notFound().build());
    }
}
