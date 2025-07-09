package com.talentstream.controller;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.validation.Valid;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.talentstream.dto.TestDTO;
import com.talentstream.dto.TestQuestionDTO;
import com.talentstream.service.TestService;

@RestController
@RequestMapping("/test")
public class TestController {

    private static final Logger LOGGER = LoggerFactory.getLogger(TestController.class);

    @Autowired
    private TestService testService;

    @PostMapping("/saveTest")
    public ResponseEntity<?> createTest(@Valid @RequestBody TestDTO testDTO, BindingResult result) {
        LOGGER.info("Received request to create test: {}", testDTO.getTestName());

        try {
            if (result.hasErrors()) {
                LOGGER.warn("Validation errors occurred while creating test.");

                Map<String, String> errors = new HashMap<>();
                List<FieldError> fieldErrors = result.getFieldErrors();
                fieldErrors.forEach(err -> errors.put(err.getField(), err.getDefaultMessage()));
                return ResponseEntity.badRequest().body(errors);
            }

            TestDTO test = testService.createTest(testDTO);
            LOGGER.info("Test '{}' created successfully with ID: {}", test.getTestName(), test.getId());
            return ResponseEntity.ok("Test saved Successfully");
        } catch (RuntimeException e) {
            LOGGER.warn("Test Already present with name: {}", testDTO.getTestName());
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (Exception e) {
            LOGGER.error("Error while creating test: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError().body("Error creating test: " + e.getMessage());
        }
    }

    @GetMapping("/getTestByName/{testName}")
    public ResponseEntity<?> getTestByName(@PathVariable String testName) {
        LOGGER.info("Fetching test details for: {}", testName);
        try {

            TestDTO test = testService.getTestByName(testName);
            LOGGER.info("Successfully retrieved test: {}", test.getTestName());
            return ResponseEntity.ok(test);
        } catch (RuntimeException e) {
            LOGGER.warn("Test not found: {}", testName);
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (Exception e) {
            LOGGER.error("Internal server error while retrieving test '{}'", testName, e);
            return ResponseEntity.internalServerError().body("Internal server error while getting test");
        }
    }

    @PutMapping("/questions/{testName}")
    public ResponseEntity<String> addQuestionsToTest(@PathVariable String testName,
            @RequestBody List<TestQuestionDTO> questionDTOs) {
        try {
            String response = testService.addQuestionsToTest(testName, questionDTOs);
            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            LOGGER.warn("Test Not found with name: {}", testName);
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (Exception e) {
            LOGGER.error("Error while creating test: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError().body("Error while adding questions: " + e.getMessage());
        }
    }
}