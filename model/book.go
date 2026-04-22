package model

import (
	"time"
)

type Book struct {
	ID              uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	Title           string    `gorm:"not null" json:"title"`
	Author          string    `gorm:"not null" json:"author"`
	ISBN            string    `gorm:"unique" json:"isbn"`
	Publisher       string    `json:"publisher"`
	PublicationDate string    `json:"publication_date"`
	Edition         string    `json:"edition"`
	Category        string    `json:"category"`
	Pages           string    `gorm:"default:0" json:"pages"`
	Copies          string    `gorm:"default:0" json:"copies"`
	Available       int       `gorm:"default:0" json:"available"`
	Reserved        int       `gorm:"default:0" json:"reserved"`
	Description     string    `gorm:"type:text" json:"description"`
	ActualImage     string    `gorm:"type:text" json:"actual_image"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}
