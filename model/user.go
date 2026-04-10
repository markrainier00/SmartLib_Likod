package model

import (
	"time"

	"gorm.io/gorm"
)

type User struct {
	ID             uint           `json:"id" gorm:"primarykey"`
	Role           string         `json:"role" gorm:"default:Student"`
	FirstName      string         `json:"firstname" gorm:"not null"`
	LastName       string         `json:"lastname" gorm:"not null"`
	Email          string         `json:"email" gorm:"uniqueIndex;not null"`
	SchoolID       string         `json:"school_id" gorm:"uniqueIndex;not null"`
	Department     string         `json:"department"`
	Program        string         `json:"program"`
	Year           string         `json:"year"`
	Status         string         `json:"status" gorm:"default:Pending"`
	Password       string         `json:"-" gorm:"not null"`
	SchoolIDImage  string         `json:"school_id_image"`
	RejectReason   string         `json:"reject_reason"`
	ViolationCount int            `json:"violation_count"`
	OffenseCount   int            `json:"offense_count"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
	DeletedAt      gorm.DeletedAt `json:"-" gorm:"index"`
}
