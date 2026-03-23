package model

import "time"

type RegistrationRequest struct {
	ID            uint      `json:"id" gorm:"primarykey"`
	UserID        uint      `json:"user_id"`
	FirstName     string    `json:"firstname"`
	LastName      string    `json:"lastname"`
	Email         string    `json:"email"`
	SchoolID      string    `json:"school_id"`
	SchoolIDImage string    `json:"school_id_image"`
	Program       string    `json:"program"`
	Year          string    `json:"year"`
	Action        string    `json:"action"`
	Reason        string    `json:"reason"`
	ActionedAt    time.Time `json:"actioned_at"`
}
