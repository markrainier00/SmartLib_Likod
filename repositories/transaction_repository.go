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

func HasActiveRequest(schoolID string, isbn string) (int64, error) {
	var count int64

	err := database.DB.Model(&model.Transaction{}).
		Where("school_id = ? AND isbn = ? AND status IN ('Pending', 'Borrowed')", schoolID, isbn).
		Count(&count).Error

	return count, err
}

func GetStudentTransaction(schoolID string) ([]model.Transaction, error) {
	var history []model.Transaction

	err := database.DB.Where("school_id = ? AND status != ?", schoolID, "Pending").Order("id desc").Find(&history).Error
	return history, err
}

func GetStudentHistory(schoolID string) ([]model.TransactionHistory, error) {
	var history []model.TransactionHistory

	err := database.DB.Where("school_id = ?", schoolID).Order("id desc").Find(&history).Error
	return history, err
}

// GetAllPendingRequests - Para sa Admin "Pending Approvals" list
func GetAllPendingRequests() ([]model.Transaction, error) {
	var requests []model.Transaction
	err := database.DB.Where("status = ?", "Pending").Order("id desc").Find(&requests).Error
	return requests, err
}

// ReleaseBookStatus - Update status from 'Pending' to 'Borrowed' (Scanner Action)
// ✅ FIX: I-update din ang updated_at para lumabas ang Date Approved sa frontend
func ReleaseBookStatus(schoolID string) error {
	return database.DB.Model(&model.Transaction{}).
		Where("school_id = ? AND status = ?", schoolID, "Pending").
		Updates(map[string]interface{}{
			"status":     "Borrowed",
			"updated_at": time.Now(),
		}).Error
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

// --- DASHBOARD STATS QUERIES ---

func GetPendingRegCount() int64 {
	var count int64
	database.DB.Model(&model.User{}).Where("status = ?", "New").Count(&count)
	return count
}

func GetPendingBorrowCount() int64 {
	var count int64
	database.DB.Model(&model.Transaction{}).Where("status = ?", "Pending").Count(&count)
	return count
}

func GetActiveBorrowCount() int64 {
	var count int64
	database.DB.Model(&model.Transaction{}).Where("status = ?", "Borrowed").Count(&count)
	return count
}
