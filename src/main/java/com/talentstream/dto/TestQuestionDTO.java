package com.talentstream.dto;

import javax.validation.constraints.*;
import java.util.List;

public class TestQuestionDTO {

    private Long id;

    @NotBlank(message = "Question cannot be blank")
    @Size(max = 500, message = "Question length must not exceed 500 characters")
    private String question;

    @NotEmpty(message = "Options cannot be empty")
    @Size(min = 2, max = 5, message = "There must be between 2 and 5 options")
    private List<@NotBlank(message = "Option cannot be blank") String> options;

    @NotBlank(message = "Answer cannot be blank")
    private String answer;
    private String difficulty;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getQuestion() {
        return question;
    }

    public void setQuestion(String question) {
        this.question = question;
    }

    public List<String> getOptions() {
        return options;
    }

    public void setOptions(List<String> options) {
        this.options = options;
    }

    public String getAnswer() {
        return answer;
    }

    public void setAnswer(String answer) {
        this.answer = answer;
    }

    public String getDifficulty() {
        return difficulty;
    }

    public void setDifficulty(String difficulty) {
        this.difficulty = difficulty;
    }

}