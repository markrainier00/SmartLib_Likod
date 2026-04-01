package model

import (
	"time"
)

type Book struct {
	ID              uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	Title           string    `gorm:"type:varchar(255);not null" json:"title"`
	Author          string    `gorm:"type:varchar(255);not null" json:"author"`
	ISBN            string    `gorm:"type:varchar(20);unique" json:"isbn"`
	Publisher       string    `gorm:"type:varchar(150)" json:"publisher"`
	PublicationDate string    `gorm:"type:varchar(50)" json:"publication_date"`
	Edition         string    `gorm:"type:varchar(50)" json:"edition"`
	Category        string    `gorm:"type:varchar(500)" json:"category"`
	Pages           string    `gorm:"default:1" json:"pages"`
	Copies          string    `gorm:"default:1" json:"copies"`
	Available       string    `gorm:"default:1" json:"available"`
	Description     string    `gorm:"type:text" json:"description"`
	ActualImage     string    `gorm:"type:text" json:"actual_image"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}
