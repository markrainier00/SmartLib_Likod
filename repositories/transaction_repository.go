package repositories

import (
	"time"

	"SmartLib_Likod/database"
	"SmartLib_Likod/model"
)

func CreateRequest(request *model.Transaction) error {
	return database.DB.Create(request).Error
}

func AddWishlist(w *model.Wishlist) error {
	return database.DB.Create(w).Error
}

func RemoveWishlist(schoolID string, isbn string) error {
	return database.DB.
		Where("school_id = ? AND isbn = ?", schoolID, isbn).
		Delete(&model.Wishlist{}).Error
}

func HasActiveBorrow(schoolID string, isbn string) (int64, error) {
	var count int64

	err := database.DB.Model(&model.Transaction{}).
		Where("school_id = ? AND isbn = ? AND status = ?", schoolID, isbn, "Borrowed").
		Count(&count).Error

	return count, err
}

func HasActiveRequest(schoolID string, isbn string) (int64, error) {
	var count int64

	err := database.DB.Model(&model.Transaction{}).
		Where("school_id = ? AND isbn = ? AND status = ?", schoolID, isbn, "Pending").
		Count(&count).Error

	return count, err
}

func GetStudentTransaction(schoolID string) ([]model.Transaction, error) {
	var history []model.Transaction

	err := database.DB.Where("school_id = ? AND status != ?", schoolID, "Pending").Order("id desc").Find(&history).Error
	return history, err
}

func GetStudentAllTransaction(schoolID string) ([]model.Transaction, error) {
	var history []model.Transaction

	err := database.DB.Where("school_id = ?", schoolID).Order("id desc").Find(&history).Error
	return history, err
}

func GetStudentHistory(schoolID string) ([]model.TransactionHistory, error) {
	var history []model.TransactionHistory

	err := database.DB.Where("school_id = ?", schoolID).Order("id desc").Find(&history).Error
	return history, err
}

func GetWholeHistory() ([]model.TransactionHistory, error) {
	var history []model.TransactionHistory

	err := database.DB.
		Order("id desc").
		Find(&history).Error

	return history, err
}

func GetAllRequests() ([]model.Transaction, error) {
	var requests []model.Transaction
	err := database.DB.Order("id desc").Find(&requests).Error
	return requests, err
}

func UpdateTransactionStatus(schoolID string, oldStatus string, newStatus string) error {
	return database.DB.Model(&model.Transaction{}).
		Where("school_id = ? AND status = ?", schoolID, oldStatus).
		Updates(map[string]interface{}{
			"status":     newStatus,
			"updated_at": time.Now(),
		}).Error
}
