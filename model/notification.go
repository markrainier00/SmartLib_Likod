package model

import "time"

type Notification struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	SchoolID  string    `gorm:"index;not null" json:"school_id"`
	Message   string    `gorm:"type:text;not null" json:"message"`
	IsRead    bool      `gorm:"default:false" json:"is_read"`
	CreatedAt time.Time `gorm:"autoCreateTime" json:"created_at"`
}
