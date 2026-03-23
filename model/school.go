package model

type School struct {
	ID         uint   `json:"id" gorm:"primaryKey"`
	Department string `json:"department"`
	Program    string `json:"program"`
	Duration   int    `json:"duration"`
}
