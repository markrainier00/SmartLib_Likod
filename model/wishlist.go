package model

import "time"

type Wishlist struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	SchoolID  string    `json:"school_id"`
	ISBN      string    `json:"isbn"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}
