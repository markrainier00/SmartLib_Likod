package model

import (
	"time"
)

type Concern struct {
	ID        uint      `json:"id" gorm:"primarykey"`
	Student   string    `json:"student"`
	Course    string    `json:"course"`
	Type      string    `json:"type"`
	Title     string    `json:"title"`
	Msg       string    `json:"msg"`
	Reply     string    `json:"reply"`
	Status    string    `json:"status" gorm:"default:Pending"`
	CreatedAt time.Time `json:"created_at"`
}
