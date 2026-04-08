package model

import (
	"time"

	"gorm.io/gorm"
)

type Transaction struct {
	ID           uint           `gorm:"primaryKey" json:"id"`
	SchoolID     string         `json:"school_id"`
	ISBN         string         `json:"isbn"`
	Status       string         `json:"status"`
	PickupDate   time.Time      `json:"pickup_date"`
	RejectReason string         `json:"reject_reason"`
	RejectDate   time.Time      `json:"reject_date"`
	BorrowDate   string         `json:"borrow_date"`
	ReturnDate   string         `json:"return_date"`
	DateReturned string         `json:"date_returned"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	DeletedAt    gorm.DeletedAt `json:"deleted_at"`
}
