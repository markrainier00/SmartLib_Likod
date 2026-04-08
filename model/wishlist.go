package model

import "time"

type Wishlist struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	SchoolID  string    `json:"school_id"`
	ISBN      string    `json:"isbn"`
	CreatedAt time.Time `json:"created_at"`
}
