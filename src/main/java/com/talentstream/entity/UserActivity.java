package com.talentstream.entity;

import javax.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "user_activity")
public class UserActivity {

    // Unique ID for each activity log
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Reference to the User who performed the action
    @Column(name = "user_id", nullable = false)
    private Long userId;

    // Type of activity (e.g., login, page_view)
    @Column(name = "action_type", nullable = false)
    private String actionType;

    // Timestamp of the activity
    @Column(name = "timestamp", nullable = false)
    private LocalDateTime timestamp;

    // Constructors, Getters, and Setters

    public UserActivity() {}

    public UserActivity(Long userId, String actionType, LocalDateTime timestamp) {
        this.userId = userId;
        this.actionType = actionType;
        this.timestamp = timestamp;
    }

    // Getter and Setter for id
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    // Getter and Setter for userId
    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    // Getter and Setter for actionType
    public String getActionType() {
        return actionType;
    }

    public void setActionType(String actionType) {
        this.actionType = actionType;
    }

    // Getter and Setter for timestamp
    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(LocalDateTime timestamp) {
        this.timestamp = timestamp;
    }
}
