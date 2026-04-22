package services

import (
	"SmartLib_Likod/database"
	"SmartLib_Likod/model"
	"SmartLib_Likod/repositories"
)

type UpdateUserStatusInput struct {
	SchoolID string `json:"school_id"`
	Status   string `json:"status"`
}

func GetWholeUsersService() ([]model.User, error) {
	var users []model.User
	result := database.DB.Find(&users)
	return users, result.Error
}

func GetAllUsersService() ([]model.User, error) {
	var users []model.User
	result := database.DB.Where("status != ?", "Archived").Find(&users)
	return users, result.Error
}

func GetPendingUsersService() ([]model.User, error) {
	var users []model.User
	result := database.DB.Where("status = ?", "Pending").Find(&users)
	return users, result.Error
}

func GetStudentUsersService() ([]model.User, error) {
	var users []model.User
	result := database.DB.Where("role = ? AND status != ? AND status != ?", "Student", "Pending", "Archived").Find(&users)
	return users, result.Error
}

func GetSpecificUserService(schoolID string) ([]model.User, error) {
	var users []model.User
	result := database.DB.Where("school_id = ?", schoolID).Find(&users)
	return users, result.Error
}

func GetAllRequestsService() ([]model.Transaction, error) {
	var transactions []model.Transaction
	result := database.DB.Find(&transactions)
	return transactions, result.Error
}

func GetRegistrationHistoryService() ([]model.RegistrationRequest, error) {
	return repositories.GetRegistrationHistory()
}
