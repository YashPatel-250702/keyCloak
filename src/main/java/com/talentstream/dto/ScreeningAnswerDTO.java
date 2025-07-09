package com.talentstream.dto;

import java.io.Serializable;

public class ScreeningAnswerDTO implements Serializable {
    private static final long serialVersionUID = 1L;

    private Long questionId;
    private String answerText;

    public ScreeningAnswerDTO() {}

    public ScreeningAnswerDTO(Long questionId, String answerText) {
        this.questionId = questionId;
        this.answerText = answerText;
    }

    public Long getQuestionId() {
        return questionId;
    }

    public void setQuestionId(Long questionId) {
        this.questionId = questionId;
    }

    public String getAnswerText() {
        return answerText;
    }

    public void setAnswerText(String answerText) {
        this.answerText = answerText;
    }

    @Override
    public String toString() {
        return "ScreeningAnswerDTO{" +
                "questionId=" + questionId +
                ", answerText='" + answerText + '\'' +
                '}';
    }
}
