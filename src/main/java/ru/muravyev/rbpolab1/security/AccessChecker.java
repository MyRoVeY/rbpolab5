package ru.muravyev.rbpolab1.security;

import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import ru.muravyev.rbpolab1.repository.SurveyAnswerRepository;
import ru.muravyev.rbpolab1.repository.SurveyParticipationRepository;
import ru.muravyev.rbpolab1.repository.SurveyQuestionRepository;
import ru.muravyev.rbpolab1.repository.SurveyRepository;

@Component("access")
@Transactional(readOnly = true)
public class AccessChecker {

    private final CurrentUser currentUser;
    private final SurveyRepository surveyRepository;
    private final SurveyQuestionRepository questionRepository;
    private final SurveyParticipationRepository participationRepository;
    private final SurveyAnswerRepository answerRepository;

    public AccessChecker(CurrentUser currentUser,
                         SurveyRepository surveyRepository,
                         SurveyQuestionRepository questionRepository,
                         SurveyParticipationRepository participationRepository,
                         SurveyAnswerRepository answerRepository) {
        this.currentUser = currentUser;
        this.surveyRepository = surveyRepository;
        this.questionRepository = questionRepository;
        this.participationRepository = participationRepository;
        this.answerRepository = answerRepository;
    }

    public boolean canManageSurvey(Long surveyId) {
        if (surveyId == null || currentUser.isAdmin()) {
            return true;
        }
        Long me = currentUser.id();
        return surveyRepository.findById(surveyId)
                .map(s -> s.getAuthor().getId().equals(me))
                .orElse(true);
    }

    public boolean canManageQuestion(Long questionId) {
        if (currentUser.isAdmin()) {
            return true;
        }
        Long me = currentUser.id();
        return questionRepository.findById(questionId)
                .map(q -> q.getSurvey().getAuthor().getId().equals(me))
                .orElse(true);
    }

    public boolean isRespondent(Long participationId) {
        if (participationId == null) {
            return true;
        }
        Long me = currentUser.id();
        return participationRepository.findById(participationId)
                .map(p -> p.getRespondent().getId().equals(me))
                .orElse(true);
    }

    public boolean canViewParticipation(Long participationId) {
        if (currentUser.isAdmin()) {
            return true;
        }
        Long me = currentUser.id();
        return participationRepository.findById(participationId)
                .map(p -> p.getRespondent().getId().equals(me)
                        || p.getSurvey().getAuthor().getId().equals(me))
                .orElse(true);
    }

    public boolean canDeleteParticipation(Long participationId) {
        return currentUser.isAdmin() || isRespondent(participationId);
    }

    public boolean canViewAnswer(Long answerId) {
        if (currentUser.isAdmin()) {
            return true;
        }
        Long me = currentUser.id();
        return answerRepository.findById(answerId)
                .map(a -> a.getParticipation().getRespondent().getId().equals(me)
                        || a.getParticipation().getSurvey().getAuthor().getId().equals(me))
                .orElse(true);
    }

    public boolean canEditAnswer(Long answerId) {
        Long me = currentUser.id();
        return answerRepository.findById(answerId)
                .map(a -> a.getParticipation().getRespondent().getId().equals(me))
                .orElse(true);
    }
}