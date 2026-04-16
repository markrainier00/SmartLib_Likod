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
	RejectReason string         `json:"reject_reason"`
	Violation    string         `json:"violation"`
	PickupDate   time.Time      `json:"pickup_date"`
	ApproveDate  time.Time      `json:"approve_date"`
	RejectDate   time.Time      `json:"reject_date"`
	BorrowDate   time.Time      `json:"borrow_date"`
	ReturnDate   time.Time      `json:"return_date"`
	DateReturned time.Time      `json:"date_returned"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	DeletedAt    gorm.DeletedAt `json:"deleted_at"`
}

type TransactionHistory struct {
	ID            uint      `gorm:"primaryKey" json:"id"`
	TransactionID uint      `json:"transaction_id"`
	SchoolID      string    `json:"school_id"`
	ISBN          string    `json:"isbn"`
	Event         string    `json:"event"`
	Staff         string    `json:"staff"`
	Date          time.Time `json:"date"`
}
