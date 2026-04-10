package services

import (
	"SmartLib_Likod/database"
	"SmartLib_Likod/model"
	"SmartLib_Likod/repositories"
)

// DAPAT NANDITO ANG MGA STRUCTS NA ITO
type ApproveInput struct {
	UserID uint `json:"user_id"`
}

type RejectInput struct {
	UserID uint   `json:"user_id"`
	Reason string `json:"reason"`
}

type UpdateUserStatusInput struct {
	SchoolID string `json:"school_id"`
	Status   string `json:"status"`
}

// DAPAT NANDITO ANG MGA FUNCTIONS NA ITO
func ApproveUserService(input ApproveInput) error {
	// ... yung logic na sinend mo kanina ...
	return nil
}

func RejectUserService(input RejectInput) error {
	// ... yung logic na sinend mo kanina ...
	return nil
}

func GetAllUsersService() ([]model.User, error) {
	var users []model.User
	result := database.DB.Find(&users)
	return users, result.Error
}

func UpdateUserStatusService(input UpdateUserStatusInput) error {
	// ... logic ...
	return nil
}

func DeleteUserService(schoolID string) error {
	// ... logic ...
	return nil
}

func GetAllRequestsService() ([]model.Transaction, error) {
	var transactions []model.Transaction
	result := database.DB.Find(&transactions)
	return transactions, result.Error
}

func GetRegistrationHistoryService() ([]model.RegistrationRequest, error) {
	return repositories.GetRegistrationHistory()
}
