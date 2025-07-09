package com.talentstream.dto;

import javax.validation.constraints.*;
import java.util.List;

public class TestDTO {
    private Long id;

    @NotBlank(message = "Test name is required")
    @Size(max = 100, message = "Test name cannot exceed 100 characters")
    private String testName;

    @NotBlank(message = "Duration is required")
    private String duration;

    @NotNull(message = "Number of questions is required")
    @Min(value = 1, message = "There must be at least 1 question")
    @Max(value = 100, message = "Number of questions cannot exceed 100")
    private Integer numberOfQuestions;

    @NotEmpty(message = "At least one topic must be covered")
    private List<@NotBlank(message = "Topic name cannot be blank") String> topicsCovered;

    private List<TestQuestionDTO> questions;

    // Getters and Setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getTestName() {
        return testName;
    }

    public void setTestName(String testName) {
        this.testName = testName;
    }

    public String getDuration() {
        return duration;
    }

    public void setDuration(String duration) {
        this.duration = duration;
    }

    public Integer getNumberOfQuestions() {
        return numberOfQuestions;
    }

    public void setNumberOfQuestions(Integer numberOfQuestions) {
        this.numberOfQuestions = numberOfQuestions;
    }

    public List<String> getTopicsCovered() {
        return topicsCovered;
    }

    public void setTopicsCovered(List<String> topicsCovered) {
        this.topicsCovered = topicsCovered;
    }

    public List<TestQuestionDTO> getQuestions() {
        return questions;
    }

    public void setQuestions(List<TestQuestionDTO> questions) {
        this.questions = questions;
    }
}