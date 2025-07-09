package com.talentstream.dto;

import java.io.Serializable;
import java.util.List;

public class ScreeningAnswersWrapperDTO implements Serializable {
    private static final long serialVersionUID = 1L;

    private List<ScreeningAnswerDTO> answers;

    public ScreeningAnswersWrapperDTO() {}

    public ScreeningAnswersWrapperDTO(List<ScreeningAnswerDTO> answers) {
        this.answers = answers;
    }

    public List<ScreeningAnswerDTO> getAnswers() {
        return answers;
    }

    public void setAnswers(List<ScreeningAnswerDTO> answers) {
        this.answers = answers;
    }

    @Override
    public String toString() {
        return "ScreeningAnswersWrapperDTO{" +
                "answers=" + answers +
                '}';
    }
}
