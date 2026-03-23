package model

import (
	"time"

	"gorm.io/gorm"
)

type Transaction struct {
	ID           uint           `gorm:"primaryKey" json:"id"`
	SchoolID     string         `gorm:"column:school_id" json:"school_id"`
	BookTitle    string         `gorm:"column:book_title" json:"book_title"`
	Author       string         `gorm:"column:author" json:"author"`
	Status       string         `gorm:"column:status" json:"status"`
	PickupDate   time.Time      `gorm:"column:pickup_date" json:"pickup_date"`
	BorrowDate   string         `gorm:"column:borrow_date" json:"borrow_date"`
	ReturnDate   string         `gorm:"column:return_date" json:"return_date"`
	DateReturned string         `gorm:"column:date_returned" json:"date_returned"`
	CreatedAt    time.Time      `gorm:"column:created_at" json:"created_at"`
	UpdatedAt    time.Time      `gorm:"column:updated_at" json:"updated_at"`
	DeletedAt    gorm.DeletedAt `gorm:"column:deleted_at" json:"deleted_at"`
}

func (Transaction) TableName() string {
	return "transactions"
}
