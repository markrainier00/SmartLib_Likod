package repositories

import (
	"SmartLib_Likod/database"
	"SmartLib_Likod/model"
)

// CreateNotification - I-save ang bagong notification sa database
func CreateNotification(notif *model.Notification) error {
	return database.DB.Create(notif).Error
}

// GetNotificationsBySchoolID - Kunin ang history ng isang student
func GetNotificationsBySchoolID(schoolID string) ([]model.Notification, error) {
	var notifs []model.Notification
	err := database.DB.Where("school_id = ?", schoolID).Order("created_at desc").Find(&notifs).Error
	return notifs, err
}
